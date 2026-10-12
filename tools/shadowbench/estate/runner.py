"""Run every estate adapter against its units under a scrubbed environment.

The mechanics mirror `tools.discovery_benchmark.runner`: a rebuilt
environment with a dead proxy, a private HOME and TMP per run, process-group
kills on timeout, and truncated capture files. The run unit is an estate
unit id (`estate`, `code:<repo>`, `home:<device>`) instead of a repository.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from shutil import rmtree
from typing import Any

from tools.discovery_benchmark.runner import MAX_CAPTURE_BYTES, RunPolicy, _wrap, scrubbed_env
from tools.shadowbench.estate.adapters import Adapter, Command, ToolConfig
from tools.shadowbench.estate.corpus import EstateCorpus

MAX_TEXT_CHARS = 400


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _slug(unit: str) -> str:
    return unit.replace(":", "__").replace("/", "_")


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
    stdout_path = out_dir / f"{index}.stdout.txt"
    stderr_path = out_dir / f"{index}.stderr.txt"
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    timeout = command.timeout or policy.timeout
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
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
            return CommandResult(
                list(command.argv), None, 0.0, False, False, stdout_path.name, stderr_path.name
            )
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
    for path in (stdout_path, stderr_path):
        if path.stat().st_size > MAX_CAPTURE_BYTES:
            with path.open("r+b") as handle:
                handle.truncate(MAX_CAPTURE_BYTES)
    ok = not timed_out and exit_code in command.ok_exit_codes
    return CommandResult(
        list(command.argv),
        exit_code,
        round(seconds, 3),
        timed_out,
        ok,
        stdout_path.name,
        stderr_path.name,
    )


def run_unit(
    adapter: Adapter,
    cfg: ToolConfig,
    unit: str,
    estate: Path,
    out_dir: Path,
    policy: RunPolicy,
) -> RunResult:
    if out_dir.exists():
        rmtree(out_dir)
    out_dir.mkdir(parents=True)
    home = out_dir / "home"
    home.mkdir()
    started = time.monotonic()
    try:
        commands = adapter.commands(cfg, unit, estate, out_dir)
    except Exception as exc:  # noqa: BLE001 - adapter bugs must not kill the matrix
        return RunResult(adapter.spec.id, unit, "error", 0.0, error=f"commands: {exc}")
    results: list[CommandResult] = []
    status = "ok"
    for index, command in enumerate(commands):
        result = run_command(command, index=index, policy=policy, out_dir=out_dir, home=home)
        results.append(result)
        if result.timed_out:
            status = "timeout"
            break
        if not result.ok:
            status = "failed"
    try:
        normalized = adapter.normalize(unit, out_dir)
    except Exception as exc:  # noqa: BLE001 - adapter bugs must not kill the matrix
        return RunResult(
            adapter.spec.id,
            unit,
            "error",
            round(time.monotonic() - started, 3),
            commands=results,
            error=f"normalize: {exc}",
        )
    if normalized.error and status == "ok":
        status = "failed"
    seconds = round(time.monotonic() - started, 3)
    predictions = [
        {
            "fact": p.fact,
            "text": p.text[:MAX_TEXT_CHARS],
            "surface": p.surface,
            "shadow": p.shadow,
        }
        for p in normalized.predictions
    ]
    result_row = RunResult(
        adapter.spec.id,
        unit,
        status,
        seconds,
        predictions=predictions,
        raw_count=normalized.raw_count,
        commands=results,
        error=normalized.error,
        detail=normalized.detail,
        incomplete=normalized.incomplete,
    )
    (out_dir / "result.json").write_text(json.dumps(result_row.to_dict(), indent=1) + "\n", encoding="utf-8")
    tmp = out_dir / "tmp"
    if tmp.exists():
        rmtree(tmp, ignore_errors=True)
    return result_row


def run_matrix(
    corpus: EstateCorpus,
    adapters: list[Adapter],
    cfg: ToolConfig,
    estate: Path,
    out_root: Path,
    policy: RunPolicy,
    *,
    workers: int = 4,
    only: set[str] | None = None,
) -> dict[str, Any]:
    out_root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "started": datetime.now(UTC).isoformat(),
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

    def _run(pair: tuple[Adapter, str]) -> RunResult:
        adapter, unit = pair
        out_dir = out_root / adapter.spec.id / _slug(unit)
        return run_unit(adapter, cfg, unit, estate, out_dir, policy)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(_run, pairs))
    manifest["results"] = [row.to_dict() for row in rows]
    manifest["finished"] = datetime.now(UTC).isoformat()
    (out_root / "runs.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest
