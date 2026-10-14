"""Run every estate adapter against its units under a scrubbed environment.

The mechanics mirror `tools.discovery_benchmark.runner`: a rebuilt
environment with a dead proxy, a private HOME and TMP per run, process-group
kills on timeout, truncated capture files, and with `--as-user` the run's
directories handed to that account. The run unit is an estate unit id
(`estate`, `code:<repo>`, `home:<device>`) instead of a repository.

Every unit runs against its own copy of the estate. Several adapters point
HOME at a home tree inside the estate while other tools scan the same tree
concurrently, so a cache or config a tool wrote there would otherwise change
the frozen corpus under every other run. The source estate must match its
freeze manifest before anything runs, each copy must match it before its unit
runs, and the source is checked again afterwards. `runs.json` records the
freeze manifest's digest, any drift found after the run, the files each tool
changed in its own copy, and the harness commit.

With `--as-user` the tool's account owns the output directory and the
estate copy while its commands run, so the runner never opens a file there
by path: its capture files and `result.json` are created afresh through a
descriptor of the directory, and a capture is measured and cut through the
descriptor the tool wrote to. Before anything reads what the account wrote
(`normalize`, the estate-change listing), both trees are handed back to the
runner and every symlink, hard link or special file in them is removed,
never followed.

A unit that timed out, exited with a code its adapter does not declare as
success, hit an adapter error, or left a link or special file among its
outputs is marked incomplete: partial or missing output never reads as a
clean negative.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.discovery_benchmark.runner import (
    MAX_CAPTURE_BYTES,
    RunPolicy,
    _chown_tree,
    _wrap,
    scrubbed_env,
)
from tools.shadowbench.estate.adapters import Adapter, Command, ToolConfig
from tools.shadowbench.estate.corpus import (
    CorpusError,
    EstateCorpus,
    UnsafeEstateError,
    estate_digests,
    estate_prefix,
    freeze_digests,
    freeze_drift,
    load_freeze,
    sha256_file,
    walk_estate,
)

MAX_TEXT_CHARS = 400
MAX_LISTED_CHANGES = 50
#: The repository the harness runs from; its commit is recorded in runs.json.
ROOT = Path(__file__).resolve().parents[3]
#: Unit directory and output file names: one plain path component, never `..`.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESERVED_OUTPUTS = re.compile(r"result\.json|home|tmp|\d+\.std(?:out|err)\.txt")
#: Opens a directory itself, never a symlink standing in for one.
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: Creates a new file; fails rather than open anything already at the name, a symlink included.
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
#: Output subdirectories that are the tool's own scratch space; no adapter reads them.
_SCRATCH_OUTPUTS = ("home/", "tmp/")


class FreezeDrift(RuntimeError):
    """The source estate differs from its freeze manifest; nothing was run."""

    def __init__(self, drift: list[str]) -> None:
        self.drift = drift
        super().__init__(f"{len(drift)} files differ from the freeze manifest")


@dataclass
class CommandResult:
    argv: list[str]
    exit_code: int | None
    seconds: float
    timed_out: bool
    ok: bool
    stdout_file: str
    stderr_file: str


@dataclass
class RunResult:
    tool: str
    unit: str
    status: str  # ok | failed | timeout | skipped | error
    seconds: float
    predictions: list[dict[str, Any]] = field(default_factory=list)
    raw_count: int = 0
    commands: list[CommandResult] = field(default_factory=list)
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    incomplete: bool = False
    #: Estate files the tool added, changed or removed in its private copy.
    estate_changes: list[str] = field(default_factory=list)
    #: Links and special files the --as-user account left in the output directory,
    #: removed before normalizing.
    removed_outputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _slug(unit: str) -> str:
    return unit.replace(":", "__").replace("/", "_")


def _git(*args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(ROOT), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def harness_revision() -> dict[str, Any]:
    """The commit the harness runs from and whether `tools/` differs from it; nulls when unknown."""
    unknown: dict[str, Any] = {"commit": None, "dirty": None}
    top = _git("rev-parse", "--show-toplevel")
    if not top or Path(top).resolve() != ROOT:
        return unknown
    head = _git("rev-parse", "--verify", "HEAD")
    if not head or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        return unknown
    status = _git("status", "--porcelain", "--untracked-files=no", "--", "tools")
    return {"commit": head, "dirty": None if status is None else bool(status)}


def _create_output(dir_fd: int, name: str) -> int:
    """Create `name` afresh in the directory open as `dir_fd` and return a write descriptor.

    With --as-user the tool's account can write the output directory, so
    whatever it left under the name (a symlink to a root-only file, say) is
    unlinked rather than written through, and the exclusive create fails if
    anything reappears there in between.
    """
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    return os.open(name, _CREATE_FLAGS, 0o644, dir_fd=dir_fd)


def _cap(fd: int) -> bool:
    """Cut the capture open as `fd` to MAX_CAPTURE_BYTES; True when it was longer.

    Measured and cut through the descriptor the tool wrote to: by path, the
    tool could have swapped its capture for a link to a file the runner would cut.
    """
    if os.fstat(fd).st_size <= MAX_CAPTURE_BYTES:
        return False
    os.ftruncate(fd, MAX_CAPTURE_BYTES)
    return True


def run_command(
    command: Command,
    *,
    index: int,
    policy: RunPolicy,
    out_dir: Path,
    home: Path,
) -> CommandResult:
    tmp = out_dir / "tmp"
    tmp.mkdir(exist_ok=True)
    env = scrubbed_env(policy, home, tmp, command.env)
    argv = _wrap(policy, command.argv, env)
    stdout_name = f"{index}.stdout.txt"
    stderr_name = f"{index}.stderr.txt"
    refusal: str | None = None
    if command.stdout_name is not None:
        if _SAFE_NAME.fullmatch(command.stdout_name) and not _RESERVED_OUTPUTS.fullmatch(command.stdout_name):
            stdout_name = command.stdout_name
        else:
            refusal = f"refused stdout_name {command.stdout_name!r}: not a plain output file name\n"
    failed = CommandResult(list(command.argv), None, 0.0, False, False, stdout_name, stderr_name)
    dir_fd = os.open(out_dir, _DIR_FLAGS)
    try:
        err = os.fdopen(_create_output(dir_fd, stderr_name), "wb")
        if refusal is not None:
            with err:
                err.write(refusal.encode())
            return failed
        try:
            out = os.fdopen(_create_output(dir_fd, stdout_name), "wb")
        except OSError:
            err.close()
            raise
    finally:
        os.close(dir_fd)
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    timeout = command.timeout or policy.timeout
    with out, err:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=out_dir,
                env=env if not policy.as_user else None,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except OSError as exc:
            err.write(str(exc).encode())
            return failed
        try:
            exit_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, 9)
            except ProcessLookupError:
                pass
            proc.wait()
        seconds = time.monotonic() - started
        # A report kept under its own name is tool output, not a log: a cut one is partial.
        report_cut = _cap(out.fileno()) and command.stdout_name is not None
        _cap(err.fileno())
    ok = not timed_out and exit_code in command.ok_exit_codes and not report_cut
    return CommandResult(
        list(command.argv), exit_code, round(seconds, 3), timed_out, ok, stdout_name, stderr_name
    )


def _reclaim(top: Path) -> list[str]:
    """Take back a tree the --as-user account could write, before the runner reads it.

    Each directory is handed to the runner and made 0755 before it is listed,
    so neither the account nor a process it left behind can add, rename or
    remove entries in it any more. Symlinks, hard links and special files are
    then removed, never followed, and regular files are handed back as well.
    Directories are entered through descriptors only. Returns the removed
    entries, relative to `top`.
    """
    uid, gid = os.geteuid(), os.getegid()
    removed: list[str] = []
    stack: list[tuple[int, str, Iterator[str]]] = []

    def enter(fd: int, rel: str) -> None:
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o755)
            names = iter(sorted(os.listdir(fd)))
        except BaseException:
            os.close(fd)
            raise
        stack.append((fd, rel, names))

    try:
        enter(os.open(top, _DIR_FLAGS), "")
        while stack:
            dir_fd, rel, names = stack[-1]
            name = next(names, None)
            if name is None:
                stack.pop()
                os.close(dir_fd)
                continue
            entry = os.lstat(name, dir_fd=dir_fd)
            if stat.S_ISDIR(entry.st_mode):
                enter(os.open(name, _DIR_FLAGS, dir_fd=dir_fd), f"{rel}{name}/")
            elif stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                os.chown(name, uid, gid, dir_fd=dir_fd, follow_symlinks=False)
                # The parent can no longer change, so `name` is still the file lstat saw.
                os.chmod(name, stat.S_IMODE(entry.st_mode) & 0o755, dir_fd=dir_fd)
            else:
                # A hard link may name a file outside the run; a FIFO would block a reader.
                os.unlink(name, dir_fd=dir_fd)
                removed.append(f"{rel}{name}")
    finally:
        for fd, _, _ in stack:
            os.close(fd)
    return removed


def _listed(names: list[str]) -> list[str]:
    listed = sorted(names)
    if len(listed) > MAX_LISTED_CHANGES:
        return [*listed[:MAX_LISTED_CHANGES], f"... and {len(listed) - MAX_LISTED_CHANGES} more"]
    return listed


def _estate_changes(copy: Path, expected: dict[str, str], removed: list[str]) -> list[str]:
    """Estate files a tool added, changed or removed in its private copy.

    Informational: tools legitimately write caches into HOME. Files the
    freeze does not know are listed without being hashed, so a large cache
    costs a directory walk only. `removed` holds the links and special files
    taken out of the copy (relative to its parent, like the freeze keys).
    """
    prefix = copy.name
    try:
        tree = walk_estate(copy)
        current = {f"{prefix}/{rel}": rel for rel in tree.files}
        changes = (current.keys() ^ expected.keys()) | {f"{prefix}/{rel}" for rel in tree.rejected}
        changes |= {
            name
            for name in current.keys() & expected.keys()
            if sha256_file(copy / current[name]) != expected[name]
        }
    except (OSError, CorpusError) as exc:
        return [f"<estate copy unreadable after the run: {type(exc).__name__}>"]
    return _listed(list(changes | set(removed)))


def _run_isolated(
    adapter: Adapter,
    cfg: ToolConfig,
    unit: str,
    estate: Path,
    out_dir: Path,
    policy: RunPolicy,
    workdir: Path,
    baseline: dict[str, str] | None,
    started: float,
) -> RunResult:
    tool = adapter.spec.id

    def elapsed() -> float:
        return round(time.monotonic() - started, 3)

    copy = workdir / estate_prefix(estate)
    shutil.copytree(estate, copy, symlinks=True)
    expected = estate_digests(estate) if baseline is None else baseline
    drift = freeze_drift(expected, estate_digests(copy))
    if drift:
        return RunResult(
            tool,
            unit,
            "error",
            elapsed(),
            error=f"private estate copy differs from the frozen estate: {', '.join(drift[:5])}",
            incomplete=True,
        )
    try:
        commands = adapter.commands(cfg, unit, copy, out_dir)
    except Exception as exc:  # noqa: BLE001 - adapter bugs must not kill the matrix
        return RunResult(tool, unit, "error", elapsed(), error=f"commands: {exc}", incomplete=True)
    results: list[CommandResult] = []
    status = "ok"
    removed: list[str] = []
    removed_from_copy: list[str] = []
    try:
        # As --as-user, the tool writes its outputs and, through HOME, its estate copy.
        _chown_tree(out_dir, policy.as_user)
        _chown_tree(workdir, policy.as_user)
        for index, command in enumerate(commands):
            result = run_command(command, index=index, policy=policy, out_dir=out_dir, home=out_dir / "home")
            results.append(result)
            if result.timed_out:
                status = "timeout"
                break
            if not result.ok:
                status = "failed"
    finally:
        if policy.as_user:
            # Nothing the account wrote is read, or written over, until the runner owns it again.
            removed = _reclaim(out_dir)
            removed_from_copy = _reclaim(workdir)
    changes = _estate_changes(copy, expected, removed_from_copy)
    # A link where a report belonged would otherwise read as a tool that found nothing.
    unsafe_report = any(not name.startswith(_SCRATCH_OUTPUTS) for name in removed)
    try:
        normalized = adapter.normalize(unit, out_dir)
    except Exception as exc:  # noqa: BLE001 - adapter bugs must not kill the matrix
        return RunResult(
            tool,
            unit,
            "error",
            elapsed(),
            commands=results,
            error=f"normalize: {exc}",
            incomplete=True,
            estate_changes=changes,
            removed_outputs=_listed(removed),
        )
    if normalized.error and status == "ok":
        status = "failed"
    predictions = [
        {
            "fact": p.fact,
            "text": p.text[:MAX_TEXT_CHARS],
            "surface": p.surface,
            "shadow": p.shadow,
        }
        for p in normalized.predictions
    ]
    return RunResult(
        tool,
        unit,
        status,
        elapsed(),
        predictions=predictions,
        raw_count=normalized.raw_count,
        commands=results,
        error=normalized.error,
        detail=normalized.detail,
        # Whatever a timed-out, failed or erroring run reported is partial.
        incomplete=normalized.incomplete or status != "ok" or unsafe_report,
        estate_changes=changes,
        removed_outputs=_listed(removed),
    )


def _write_result(out_dir: Path, row: RunResult) -> None:
    dir_fd = os.open(out_dir, _DIR_FLAGS)
    try:
        fd = _create_output(dir_fd, "result.json")
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(row.to_dict(), indent=1) + "\n")


def run_unit(
    adapter: Adapter,
    cfg: ToolConfig,
    unit: str,
    estate: Path,
    out_dir: Path,
    policy: RunPolicy,
    *,
    baseline: dict[str, str] | None = None,
    workdir: Path | None = None,
) -> RunResult:
    """Run one adapter on one unit against a private copy of `estate`.

    The copy must match `baseline` (the estate's `estate_digests`; computed
    from `estate` when omitted) before anything runs. It lives in `workdir`,
    which is created here (a fresh temporary directory by default) and
    removed afterwards. Once the directories exist, every outcome, an
    unexpected exception included, is written to `out_dir/result.json`.
    """
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    (out_dir / "home").mkdir()
    (out_dir / "tmp").mkdir()
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="shadowbench-estate-"))
    else:
        workdir.mkdir(parents=True)
    started = time.monotonic()
    try:
        row = _run_isolated(adapter, cfg, unit, estate, out_dir, policy, workdir, baseline, started)
    except Exception as exc:  # noqa: BLE001 - one unit's failure is recorded, not raised
        row = RunResult(
            adapter.spec.id,
            unit,
            "error",
            round(time.monotonic() - started, 3),
            error=f"{type(exc).__name__}: {exc}",
            incomplete=True,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(out_dir / "tmp", ignore_errors=True)
    # The account may still own out_dir if the run stopped early: never write by path.
    _write_result(out_dir, row)
    return row


def _drift_after(recorded: dict[str, str], corpus_path: Path, estate: Path) -> list[str]:
    try:
        return freeze_drift(recorded, freeze_digests(corpus_path, estate))
    except UnsafeEstateError as exc:
        return [f"{entry} (symlink or special file)" for entry in exc.entries]
    except (OSError, CorpusError) as exc:
        return [f"<estate unreadable after the run: {type(exc).__name__}: {exc}>"]


def run_matrix(
    corpus: EstateCorpus,
    adapters: list[Adapter],
    cfg: ToolConfig,
    estate: Path,
    out_root: Path,
    policy: RunPolicy,
    *,
    freeze: Path,
    corpus_path: Path,
    workers: int = 4,
    only: set[str] | None = None,
) -> dict[str, Any]:
    """Run every adapter on its units and write `runs.json` under `out_root`.

    Raises FreezeDrift before anything runs when `estate` and `corpus_path`
    differ from the `freeze` manifest; drift found after the run is recorded
    in the manifest's `freeze.drift_after`.
    """
    recorded = load_freeze(freeze)
    drift = freeze_drift(recorded, freeze_digests(corpus_path, estate))
    if drift:
        raise FreezeDrift(drift)
    prefix = estate_prefix(estate) + "/"
    baseline = {name: digest for name, digest in recorded.items() if name.startswith(prefix)}
    out_root.mkdir(parents=True, exist_ok=True)
    revision = harness_revision()
    manifest: dict[str, Any] = {
        "started": datetime.now(UTC).isoformat(),
        "harness_commit": revision["commit"],
        "harness_dirty": revision["dirty"],
        "freeze": {"sha256": sha256_file(freeze), "files": len(recorded), "drift_after": []},
        "policy": {
            "timeout": policy.timeout,
            "as_user": policy.as_user,
            "path": policy.path,
            "extra_path": list(policy.extra_path),
            "keep_network": policy.keep_network,
        },
        "workers": workers,
        "tool_versions": {},
        "tools_skipped": {},
        "results": [],
    }
    pairs: list[tuple[Adapter, str]] = []
    for adapter in adapters:
        if only and adapter.spec.id not in only:
            continue
        reason = adapter.unavailable_reason(cfg)
        if reason:
            manifest["tools_skipped"][adapter.spec.id] = reason
            continue
        manifest["tool_versions"][adapter.spec.id] = adapter.version(cfg)
        for unit in adapter.units(cfg, estate, corpus):
            pairs.append((adapter, unit))

    scratch = Path(tempfile.mkdtemp(prefix="shadowbench-estate-"))
    try:
        # An --as-user tool can reach its own estate copy but not list the others.
        scratch.chmod(0o711)
        for tool in sorted({adapter.spec.id for adapter, _ in pairs}):
            (scratch / tool).mkdir()
            (scratch / tool).chmod(0o711)

        def _run(pair: tuple[Adapter, str]) -> RunResult:
            adapter, unit = pair
            slug = _slug(unit)
            # No directory can safely be named after this unit, so it has a runs.json row only.
            if not _SAFE_NAME.fullmatch(slug):
                return RunResult(
                    adapter.spec.id, unit, "error", 0.0, error=f"unsafe unit id {unit!r}", incomplete=True
                )
            try:
                return run_unit(
                    adapter,
                    cfg,
                    unit,
                    estate,
                    out_root / adapter.spec.id / slug,
                    policy,
                    baseline=baseline,
                    workdir=scratch / adapter.spec.id / slug,
                )
            except Exception as exc:  # noqa: BLE001 - one unit's failure must not kill the matrix
                return RunResult(
                    adapter.spec.id, unit, "error", 0.0, error=f"{type(exc).__name__}: {exc}", incomplete=True
                )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(_run, pairs))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    manifest["results"] = [row.to_dict() for row in rows]
    manifest["freeze"]["drift_after"] = _drift_after(recorded, corpus_path, estate)
    manifest["finished"] = datetime.now(UTC).isoformat()
    (out_root / "runs.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest
