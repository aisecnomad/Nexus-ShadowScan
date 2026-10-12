"""Run every adapter on every case it supports, in isolation, and store normalized results.

``python -m tools.shadowbench.cases run --corpus corpus.json --tools tools.json --out results/``
(optional ``--only a,b``, ``--surfaces x,y``, ``--cases id,...``, ``--workers 4``)

For each (tool, case) the runner materializes the case under a scratch
directory, asks the adapter for its invocations, and executes them through
``stage.py`` inside fresh network, PID and mount namespaces (``unshare``), with
the case's mock services and inert processes present. The adapter then
normalizes the output into entities. One JSONL row per (tool, case) goes to
``<out>/<tool>.jsonl``; verbatim tool output goes to ``<out>/raw/<tool>/``.

Each run gets ``<scratch>/<tool>-<case>-XXXX/`` (mode 0711) holding ``work/``,
the tool's tree, which belongs to uid/gid 65534 for the run, and ``control/``
(root only), where the stage spec and the stage's result stay out of the
tool's reach. Tools run as 65534 with ``/root`` and ``/home`` hidden (see
``stage.py``), so the scratch directory, ``tool_root`` (by default the
directory holding ``tools.json``) and every path in ``tools.json`` must lie
outside those and be reachable by that uid. Every run's ``work/`` belongs to
the same uid, so the scratch directory must also belong to the runner and give
group and other nothing but search (0711, as the runner creates it), or a tool
could list it and reach a concurrent run's tree. The runner refuses to start
otherwise. Before the adapter reads the tool's output as root, any symlink the
tool left that leads out of ``work/`` and any FIFO, socket or device node in it
is removed.

A crash, timeout or unreadable output is recorded as ``error`` and never as a
clean negative. A run that exits outside the adapter's accepted codes but still
reports entities keeps them and is flagged ``incomplete``. On a timeout the
runner kills ``unshare``'s process group; with ``--kill-child`` and ``--pid``
that takes down every process in the namespace before the work tree is
removed. ``runtime/live`` rows carry the pid map so reported pids are
translated to the corpus's ``proc:<index>`` keys before scoring.

Case and checkout ids from the corpus name directories, so they must match
``[A-Za-z0-9._-]+``. A code case may not also carry files, and no input file
is written through a symlink.
"""

from __future__ import annotations

import argparse
import errno
import gzip
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.adapters.registry import load_adapters
from tools.shadowbench.cases.contract import (
    SYSTEM_PATH,
    Adapter,
    AdapterResult,
    MaterializedCase,
    RunResult,
    ToolEnv,
    supports,
)
from tools.shadowbench.cases.corpus import Case, Corpus, corpus_digest, load_corpus
from tools.shadowbench.cases.stage import HIDDEN, build_fakeproc

STAGE_TIMEOUT_GRACE = 120
KILL_GRACE = 10.0
TOOL_UID = TOOL_GID = 65534
"""The identity tools and inert processes run as (``nobody``/``nogroup`` on most systems)."""

_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")


def safe_name(value: str, what: str) -> str:
    """Return a corpus-supplied identifier that is safe as a single path component."""
    if not _SAFE_NAME.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"unsafe {what} {value!r}: expected [A-Za-z0-9._-]+")
    return value


def _write_input(inputs: Path, rel: str, content: str) -> None:
    """Write ``inputs/<rel>`` without following a symlink at any step of the path."""
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe input path {rel!r}")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(inputs, dir_flags)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, dir_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644, dir_fd=fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError(f"refusing to write input {rel!r} through a symlink or a file") from exc
        raise
    finally:
        os.close(fd)
    with os.fdopen(leaf, "w", encoding="utf-8") as fh:
        fh.write(content)


def materialize(case: Case, root: Path, checkouts: Path | None = None) -> MaterializedCase:
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    if case.checkout:
        if case.files:
            # A copied repository may hold symlinks; nothing from the corpus is written into it.
            raise ValueError(f"case {case.case_id} carries files beside its checkout")
        if checkouts is None:
            raise RuntimeError("code cases need --checkouts (fetched with tools.discovery_benchmark fetch)")
        name = safe_name(str(case.checkout["id"]), "checkout id")
        base = checkouts.resolve()
        src = (base / name).resolve()
        if src == base or not src.is_relative_to(base):
            raise ValueError(f"checkout {name} resolves to {src}, outside {base}")
        head = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        )
        if head.stdout.strip() != case.checkout["commit"]:
            raise RuntimeError(f"checkout {src} is not at {case.checkout['commit']}")
        shutil.copytree(src, inputs / "repo", symlinks=True)
    for rel, content in case.files.items():
        _write_input(inputs, rel, content)
    home = inputs / "home" if case.surface == "endpoint" else None
    if home is not None:
        home.mkdir(exist_ok=True)
    (root / "case.json").write_text(
        json.dumps({"id": case.case_id, "surface": case.surface, "modality": case.modality}), encoding="utf-8"
    )
    return MaterializedCase(
        case.case_id,
        case.surface,
        case.modality,
        case.family,
        root,
        inputs,
        home=home,
        processes=list(case.processes),
        services=list(case.services),
    )


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    """Hand a tree the runner built to the tool's identity without following any symlink in it."""
    os.lchown(path, uid, gid)
    for top, dirs, files in os.walk(path):
        for name in (*dirs, *files):
            os.lchown(os.path.join(top, name), uid, gid)


def _drop_unsafe_entries(work: Path) -> int:
    """Remove what the tool left that the adapter, reading as root on the host, must not open.

    The tool ran as uid 65534 with ``/root`` and ``/home`` hidden, but its output is read here
    with neither restriction: a symlink it planted could lead to a host file it could never
    read itself, and a FIFO would block the read forever. Symlinks that stay inside ``work``
    are kept.
    """
    top = os.path.realpath(work)
    removed = 0
    for parent, dirs, files in os.walk(work):
        for name in [*dirs, *files]:
            path = os.path.join(parent, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
                continue
            if stat.S_ISLNK(mode) and os.path.commonpath([top, os.path.realpath(path)]) == top:
                continue
            os.unlink(path)
            removed += 1
            if name in dirs:
                dirs.remove(name)
    return removed


def prepare_scratch(scratch: Path | None) -> Path:
    """The scratch directory, made 0711 when the runner creates it; an existing one is left as it is.

    Every run's ``work/`` belongs to the same uid 65534, so the scratch directory must not let a
    tool list it and find another run's tree; ``isolation_problems`` refuses one that does.
    """
    if scratch is None:
        path = Path(tempfile.mkdtemp(prefix="shadowbench-"))
        path.chmod(0o711)
        return path
    path = scratch.resolve()  # the stage runs from /, not from here
    if not path.exists():
        path.mkdir(parents=True)
        path.chmod(0o711)
    return path


def isolation_problems(scratch: Path, env: ToolEnv) -> list[str]:
    """Why tools running as uid 65534 with ``/root`` and ``/home`` hidden could not run from here."""
    hidden = [Path(p).resolve() for p in HIDDEN]

    def hidden_root(path: Path) -> Path | None:
        resolved = path.resolve()
        return next((h for h in hidden if resolved.is_relative_to(h)), None)

    problems: list[str] = []
    covered = hidden_root(scratch)
    if covered is not None:
        problems.append(f"scratch directory {scratch} lies under {covered}, which the stage hides from tools")
    else:
        for part in (scratch.resolve(), *scratch.resolve().parents):
            if not os.stat(part).st_mode & stat.S_IXOTH:
                problems.append(f"uid {TOOL_UID} cannot traverse {part} to reach scratch directory {scratch}")
                break
        info = os.stat(scratch)
        if info.st_uid != os.geteuid():
            problems.append(f"scratch directory {scratch} is owned by uid {info.st_uid}, not the runner's")
        if info.st_mode & 0o066:
            problems.append(
                f"scratch directory {scratch} is mode {stat.S_IMODE(info.st_mode):04o}; a tool could list"
                " it and reach another run's work tree (chmod 0711)"
            )
    # Adapters derive data paths from tool_root, which defaults to the directory holding tools.json.
    paths: list[tuple[str, str]] = [("tool_root", str(env.tool_root))]
    tools = env.config.get("tools")
    tools = tools if isinstance(tools, dict) else {}
    for name, cfg in sorted(tools.items()):
        if not isinstance(cfg, dict):
            continue
        for key, value in sorted(cfg.items()):
            if isinstance(value, str) and value.startswith("/"):
                paths.append((f"tools.{name}.{key}", value))
    for label, value in paths:
        covered = hidden_root(Path(value))
        if covered is not None:
            problems.append(f"{label} = {value} lies under {covered}, which the stage hides from tools")
    return problems


def stage_command(spec_path: Path, out_path: Path) -> list[str]:
    """The stage's command line: no network, its own PID and mount namespaces, gone when unshare dies.

    ``-P`` keeps the working directory off ``sys.path``; the stage is found through ``PYTHONPATH``.
    """
    return [
        "unshare",
        "--net",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount",
        "--propagation",
        "private",
        "--mount-proc",
        "--",
        sys.executable,
        "-P",
        "-m",
        f"{__package__}.stage",
        str(spec_path),
        str(out_path),
    ]


def _kill_stage(proc: subprocess.Popen[bytes]) -> None:
    """Kill unshare and the stage; the stage is the namespace's init, so every tool process dies too."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.communicate(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        try:
            proc.wait(timeout=KILL_GRACE)
        except subprocess.TimeoutExpired:
            pass


def _stage(spec: dict[str, Any], control: Path, repo: Path, timeout: float) -> dict[str, Any]:
    """Run the stage on ``spec``; its spec and result files live in ``control``, never in the work tree."""
    spec_path = control / "stage_spec.json"
    out_path = control / "stage_out.json"
    full = {**spec, "run_as": [TOOL_UID, TOOL_GID], "host_mnt_ns": os.readlink("/proc/self/ns/mnt")}
    spec_path.write_text(json.dumps(full), encoding="utf-8")
    env = {
        "PATH": SYSTEM_PATH,
        "PYTHONPATH": str(repo),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    proc = subprocess.Popen(
        stage_command(spec_path, out_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd="/",  # never a directory the stage then hides; its children would inherit it
        start_new_session=True,
    )
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_stage(proc)
        return _stage_error(f"stage timed out after {timeout:.0f}s")
    if not out_path.exists():
        stderr = err.decode("utf-8", "replace")[-500:]
        return _stage_error(f"stage produced no output (exit {proc.returncode}): {stderr}")
    try:
        result = json.loads(out_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return _stage_error(f"stage output unreadable: {exc}")
    if not isinstance(result, dict):
        return _stage_error("stage output is not an object")
    return result


def _stage_error(message: str) -> dict[str, Any]:
    return {"error": message, "runs": [], "processes": []}


def _with_note(note: str, extra: str) -> str:
    return (note + "; " if note else "") + extra


def run_one(
    adapter: Adapter,
    case: Case,
    env: ToolEnv,
    scratch: Path,
    repo: Path,
    fakeproc: Path,
    checkouts: Path | None,
) -> dict[str, Any]:
    prefix = f"{adapter.name}-{safe_name(case.case_id, 'case id')}-"
    run_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=scratch))
    work = run_dir / "work"
    control = run_dir / "control"
    row: dict[str, Any] = {
        "tool": adapter.name,
        "case": case.case_id,
        "surface": case.surface,
        "modality": case.modality,
        "family": case.family,
        "label": case.label,
        "difficulty": case.difficulty,
    }
    started = time.monotonic()
    try:
        # The tool may pass through run_dir to work/, but cannot list it or enter control/.
        run_dir.chmod(0o711)
        work.mkdir(mode=0o700)
        control.mkdir(mode=0o700)
        mat = materialize(case, work / "case", checkouts)
        invocations = adapter.invocations(mat, env, work)
        spec = {
            "services": mat.services,
            "processes": mat.processes if case.modality == "live" else [],
            "fakeproc": str(fakeproc),
            "work": str(work),
            "invocations": [
                {
                    "argv": list(inv.argv),
                    "cwd": str(inv.cwd),
                    "env": inv.env,
                    "timeout": inv.timeout,
                    "stdin": inv.stdin,
                }
                for inv in invocations
            ],
        }
        total_timeout = sum(inv.timeout for inv in invocations) + STAGE_TIMEOUT_GRACE
        _chown_tree(work, TOOL_UID, TOOL_GID)
        staged = _stage(spec, control, repo, total_timeout)
        unsafe = _drop_unsafe_entries(work)
        runs = [
            RunResult(
                int(r["code"]), str(r["stdout"]), str(r["stderr"]), float(r["seconds"]), bool(r["timed_out"])
            )
            for r in staged.get("runs", [])
        ]
        pid_map = {int(p["pid"]): int(p["index"]) for p in staged.get("processes", [])}
        bad_exit: int | None = None
        if staged.get("error") or len(runs) != len(invocations):
            result = AdapterResult(
                "error", note=f"stage: {staged.get('error') or 'missing invocation results'}"
            )
        elif any(r.timed_out for r in runs):
            result = AdapterResult("error", note=f"timed out after {max(r.seconds for r in runs):.0f}s")
        elif any(r.code not in inv.ok_codes for r, inv in zip(runs, invocations, strict=True)):
            bad = next(
                (r, inv) for r, inv in zip(runs, invocations, strict=True) if r.code not in inv.ok_codes
            )
            result = adapter.normalize(mat, work, runs)
            if result.status == "ok" and not result.entities:
                result = AdapterResult(
                    "error",
                    note=f"exit {bad[0].code}: {(bad[0].stderr or bad[0].stdout)[-300:].strip()}",
                    raw=result.raw,
                )
            elif result.status == "ok":
                # What a failed run printed is kept, but it may have stopped before reading everything.
                bad_exit = bad[0].code
        else:
            result = adapter.normalize(mat, work, runs)
        if case.modality == "live":
            translated = []
            harness = 0
            for e in result.entities:
                if e.key.startswith("process:"):
                    pid = int(e.key.split(":", 1)[1]) if e.key.split(":", 1)[1].isdigit() else -1
                    if pid in pid_map:
                        translated.append(type(e)(e.kind, f"proc:{pid_map[pid]}", e.label, e.attributes))
                    else:
                        harness += 1
                else:
                    translated.append(e)
            result.entities = translated
            if harness:
                result.note = _with_note(result.note, f"{harness} harness/self process reports ignored")
        if bad_exit is not None:
            result.note = _with_note(result.note, f"exit {bad_exit} is outside the accepted codes")
        if unsafe:
            result.note = _with_note(result.note, f"{unsafe} unsafe links or special files removed from work")
        row.update(result.to_json())
        row["seconds"] = round(sum(r.seconds for r in runs), 3)
        row["incomplete"] = bool(result.raw.get("incomplete")) or bad_exit is not None
        row["raw"] = {"runs": [asdict(r) for r in runs], "adapter": result.raw}
    except Exception as exc:  # noqa: BLE001 - an adapter bug is an error row, never a crash of the whole run
        row.update(
            {
                "status": "error",
                "entities": [],
                "note": f"adapter exception: {type(exc).__name__}: {exc}"[:400],
            }
        )
        row["seconds"] = round(time.monotonic() - started, 3)
        row["incomplete"] = False
        row["raw"] = {}
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    return row


def run_tool(
    adapter: Adapter,
    cases: list[Case],
    env: ToolEnv,
    out: Path,
    workers: int,
    scratch: Path,
    repo: Path,
    fakeproc: Path,
    checkouts: Path | None,
) -> dict[str, Any]:
    for case in cases:
        safe_name(case.case_id, "case id")
    rows_path = out / f"{adapter.name}.jsonl"
    raw_dir = out / "raw" / adapter.name
    raw_dir.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    rows: dict[str, dict[str, Any]] = {}
    started = time.time()

    def task(case: Case) -> None:
        if not supports(adapter, case.surface, case.modality):
            row = {
                "tool": adapter.name,
                "case": case.case_id,
                "surface": case.surface,
                "modality": case.modality,
                "family": case.family,
                "label": case.label,
                "difficulty": case.difficulty,
                "status": "unsupported",
                "entities": [],
                "note": "",
                "seconds": 0.0,
                "incomplete": False,
            }
        else:
            row = run_one(adapter, case, env, scratch, repo, fakeproc, checkouts)
            raw = row.pop("raw", {})
            with gzip.open(raw_dir / f"{case.case_id}.json.gz", "wt", encoding="utf-8") as fh:
                json.dump(raw, fh)
        with lock:
            rows[case.case_id] = row

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(task, cases))
    with rows_path.open("w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(rows[case.case_id], ensure_ascii=False) + "\n")
    statuses: dict[str, int] = {}
    for row in rows.values():
        statuses[str(row["status"])] = statuses.get(str(row["status"]), 0) + 1
    return {
        "tool": adapter.name,
        "version": adapter.version(env),
        "seconds": round(time.time() - started, 1),
        "statuses": statuses,
    }


def unsafe_ids(cases: list[Case]) -> list[str]:
    """Case and checkout ids that cannot name a directory safely."""
    problems: list[str] = []
    for case in cases:
        names = [("case id", case.case_id)]
        if case.checkout:
            names.append(("checkout id", str(case.checkout.get("id"))))
        for what, value in names:
            try:
                safe_name(value, what)
            except ValueError as exc:
                problems.append(f"{case.case_id!r}: {exc}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument(
        "--tools", type=Path, required=True, help="tools.json: {tool_root, tools: {name: {bin, ...}}}"
    )
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", default="", help="comma-separated adapter names")
    ap.add_argument("--surfaces", default="", help="comma-separated surfaces to run")
    ap.add_argument("--cases", default="", help="comma-separated case ids")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--scratch", type=Path, default=None)
    ap.add_argument(
        "--checkouts", type=Path, default=None, help="directory of pinned repository checkouts for code cases"
    )
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        print(
            f"the runner needs root for unshare --net --pid --mount and to run tools as uid {TOOL_UID}",
            file=sys.stderr,
        )
        return 2
    if shutil.which("unshare", path=SYSTEM_PATH) is None:
        print(f"unshare (util-linux) is not on {SYSTEM_PATH}", file=sys.stderr)
        return 2
    corpus: Corpus = load_corpus(args.corpus)
    bad_ids = unsafe_ids(corpus.cases)
    if bad_ids:
        print("\n".join(bad_ids), file=sys.stderr)
        return 2
    env = ToolEnv.load(args.tools)
    repo = Path(__file__).resolve().parents[3]
    adapters, problems = load_adapters()
    for name, problem in problems.items():
        print(f"adapter module {name} skipped: {problem}", file=sys.stderr)
    only = {s for s in args.only.split(",") if s}
    chosen = [a for n, a in adapters.items() if not only or n in only]
    cases = corpus.cases
    if args.surfaces:
        wanted = {s for s in args.surfaces.split(",") if s}
        cases = [c for c in cases if c.surface in wanted]
    if args.cases:
        ids = {s for s in args.cases.split(",") if s}
        cases = [c for c in cases if c.case_id in ids]
    scratch = prepare_scratch(args.scratch)
    isolation = isolation_problems(scratch, env)
    if isolation:
        print("\n".join(isolation), file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    fakeproc = build_fakeproc(scratch / "fakeproc")
    manifest: dict[str, Any] = {
        "started": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "corpus": str(args.corpus),
        "corpus_sha256": corpus_digest(args.corpus),
        "generator_digest": corpus.generator_digest,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "workers": args.workers,
        "cases": len(cases),
        "tools": {},
        "skipped_adapters": problems,
    }
    for adapter in chosen:
        reason = adapter.unavailable_reason(env)
        if reason:
            print(f"{adapter.name}: not run ({reason})")
            manifest["tools"][adapter.name] = {"skipped": reason}
            continue
        print(f"{adapter.name}: running {len(cases)} cases ...", flush=True)
        summary = run_tool(
            adapter, cases, env, args.out, args.workers, scratch, repo, fakeproc, args.checkouts
        )
        print(f"  {summary}")
        manifest["tools"][adapter.name] = summary
    manifest["finished"] = datetime.now(UTC).replace(microsecond=0).isoformat()
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
