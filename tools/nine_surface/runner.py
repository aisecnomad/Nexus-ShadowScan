"""Run every adapter on every case it supports, in isolation, and store normalized results.

``python -m tools.nine_surface run --corpus corpus.json --tools tools.json --out results/``
(optional ``--only a,b``, ``--surfaces x,y``, ``--cases id,...``, ``--workers 4``)

For each (tool, case) the runner materializes the case under a scratch
directory, asks the adapter for its invocations, and executes them through
``stage.py`` inside fresh network and PID namespaces (``unshare``), with the
case's mock services and inert processes present. The adapter then normalizes
the output into entities. One JSONL row per (tool, case) goes to
``<out>/<tool>.jsonl``; verbatim tool output goes to ``<out>/raw/<tool>/``.

A crash, timeout or unreadable output is recorded as ``error`` and never as a
clean negative. ``runtime/live`` rows carry the pid map so reported pids are
translated to the corpus's ``proc:<index>`` keys before scoring.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import shutil
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

from tools.nine_surface.adapters.registry import load_adapters
from tools.nine_surface.contract import Adapter, AdapterResult, MaterializedCase, RunResult, ToolEnv, supports
from tools.nine_surface.corpus import Case, Corpus, corpus_digest, load_corpus
from tools.nine_surface.stage import build_fakeproc

STAGE_TIMEOUT_GRACE = 120


def materialize(case: Case, root: Path, checkouts: Path | None = None) -> MaterializedCase:
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    if case.checkout:
        if checkouts is None:
            raise RuntimeError("code cases need --checkouts (fetched with tools.discovery_benchmark fetch)")
        src = checkouts / str(case.checkout["id"])
        head = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        )
        if head.stdout.strip() != case.checkout["commit"]:
            raise RuntimeError(f"checkout {src} is not at {case.checkout['commit']}")
        shutil.copytree(src, inputs / "repo", symlinks=True)
    for rel, content in case.files.items():
        path = inputs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
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


def _stage(spec: dict[str, Any], work: Path, repo: Path, timeout: float) -> dict[str, Any]:
    spec_path = work / "stage_spec.json"
    out_path = work / "stage_out.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    cmd = [
        "unshare",
        "--net",
        "--pid",
        "--fork",
        "--mount-proc",
        "--",
        sys.executable,
        "-m",
        "tools.nine_surface.stage",
        str(spec_path),
        str(out_path),
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(repo),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False, cwd=str(repo)
        )
    except subprocess.TimeoutExpired:
        return {"error": "stage timed out", "runs": [], "processes": []}
    if not out_path.exists():
        return {
            "error": f"stage produced no output (exit {proc.returncode}): {proc.stderr[-500:]}",
            "runs": [],
            "processes": [],
        }
    result: dict[str, Any] = json.loads(out_path.read_text(encoding="utf-8"))
    return result


def run_one(
    adapter: Adapter,
    case: Case,
    env: ToolEnv,
    scratch: Path,
    repo: Path,
    fakeproc: Path,
    checkouts: Path | None,
) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix=f"{adapter.name}-{case.case_id}-", dir=scratch))
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
        staged = _stage(spec, work, repo, total_timeout)
        runs = [
            RunResult(
                int(r["code"]), str(r["stdout"]), str(r["stderr"]), float(r["seconds"]), bool(r["timed_out"])
            )
            for r in staged.get("runs", [])
        ]
        pid_map = {int(p["pid"]): int(p["index"]) for p in staged.get("processes", [])}
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
                result.note = (
                    result.note + "; " if result.note else ""
                ) + f"{harness} harness/self process reports ignored"
        row.update(result.to_json())
        row["seconds"] = round(sum(r.seconds for r in runs), 3)
        row["incomplete"] = bool(result.raw.get("incomplete"))
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
        shutil.rmtree(work, ignore_errors=True)
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
        print("the runner needs root for unshare --net --pid --mount-proc", file=sys.stderr)
        return 2
    corpus: Corpus = load_corpus(args.corpus)
    env = ToolEnv.load(args.tools)
    repo = Path(__file__).resolve().parents[2]
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
    args.out.mkdir(parents=True, exist_ok=True)
    scratch = args.scratch or Path(tempfile.mkdtemp(prefix="nine-surface-"))
    scratch.mkdir(parents=True, exist_ok=True)
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
