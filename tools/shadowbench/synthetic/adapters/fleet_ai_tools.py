"""Fleet's osquery ``ai_tools`` table, run outside osquery, on endpoint/home and runtime/live.

Source: ``orbit/pkg/table/ai_tools`` of github.com/fleetdm/fleet (MIT; a vendored
copy of karmine05/agentic-detector v0.3.0 with Fleet's hardening), taken from
``main`` at commit cf1217bafcd5cdce367165b1c604f94ed559e3d0 (2026-10-11) with a
sparse checkout of that directory. Fleet's module declares ``go 1.27.2`` and
would pull the whole repository, so the package is copied into a tiny module
(``<tool_root>/third_party/fleet-ai-tools``, import prefix rewritten, tests
dropped, dependencies pinned to Fleet's go.mod versions) whose
``cmd/fleet-ai-tools`` calls ``ai_tools.Generate(ctx, table.QueryContext{})`` and
prints the rows as JSON. It builds with Go 1.24 and CGO_ENABLED=0::

    cd <tool_root>/third_party/fleet-ai-tools
    CGO_ENABLED=0 go build -trimpath -o <tool_root>/bin/fleet-ai-tools ./cmd/fleet-ai-tools

Invocation (no flags; ``HOME`` is the case home or the work dir)::

    fleet-ai-tools

The table enumerates homes as ``/home/*``, ``/root`` and ``os.UserHomeDir()``
(``$HOME``), so the case home is scanned alongside the real homes on the host
and this adapter keeps only rows whose ``path`` lies under the case home (the
rest stay in ``raw``). Output is a JSON array of string-valued rows with the
table's columns: ``type`` (``mcp_server``, ``agents``, ``agent_instruction``,
``apps``, ``ide_plugins``, ``browser_extension``, ``sockets``), ``name``,
``identifier``, ``path``, ``source`` (the client or ``process``/``evidence``),
``category``, ``confidence``, ``evidence``, ``endpoint``, ``location``, ``pid``,
``port``, ``running``, ``risk_flags``, ``sha256``, ``uid``, ``username``,
``version``, ``detail`` (JSON). Observed on the probe home: ``mcp_server`` rows
for every server in ``.claude.json`` (including the per-project ``projects.*``
servers), ``.cursor/mcp.json`` (each server twice), ``.codex/config.toml`` and
``.config/Code/User/mcp.json``, and ``agents`` rows citing the tool home
(``.claude``, ``.cursor``). The table's config catalogue (``internal/mcp/mcp.go``)
also covers ``.mcp.json``, ``.codeium/windsurf/mcp_config.json``,
``claude_desktop_config.json``, Zed, Cline, Roo, Jan, ``.gemini/config/mcp_config.json``,
``.openclaw`` and ``.grok/config.toml``, and ``agent_instruction`` rows come from
``.claude/CLAUDE.md``, ``.codex/AGENTS.md``, ``.gemini/GEMINI.md`` and project
instruction files found by a bounded walk. It does not read
``.gemini/settings.json`` or ``.claude/settings.json`` as MCP configs.

Mapping, endpoint/home: a row whose ``path`` is under the home becomes
``artifact:<relative path>``; ``mcp_server``, ``agents`` and
``agent_instruction`` rows are labelled ``agent``, ``apps``, ``ide_plugins``
and ``browser_extension`` rows ``llm``; ``sockets`` rows have no path and are
ignored here. The strongest label wins when rows share a path.

Mapping, runtime/live: a row with a non-zero ``pid`` becomes ``process:<pid>``:
``mcp_server`` rows (declared servers matched to a process, or ``source``
``process`` rows for any process whose command line contains
``modelcontextprotocol``, ``mcp-server`` or ``mcp_server``) and ``agents`` rows
are ``agent``; ``sockets`` rows whose ``category`` starts with ``mcp`` are
``agent`` and other sockets (local inference ports such as 11434, AI API
egress) and ``apps`` rows are ``llm``. In the probe, inert processes named
``claude``, ``ollama`` and ``codex`` with no home artifacts produced no row (a
running process alone scores below the table's emit floor); the three
MCP-marker processes each produced a ``mcp_server`` row with its pid. The
wrapper drops the row for its own pid, which the ``mcp_server`` marker would
otherwise match through a ``--types mcp_server`` argument.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.shadowbench.synthetic.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    relative_artifact,
    tail,
)

TOOL = "fleet-ai-tools"

HOME_LABELS: Mapping[str, str] = {
    "mcp_server": "agent",
    "agents": "agent",
    "agent_instruction": "agent",
    "apps": "llm",
    "ide_plugins": "llm",
    "browser_extension": "llm",
}
PROCESS_LABELS: Mapping[str, str] = {
    "mcp_server": "agent",
    "agents": "agent",
    "apps": "llm",
    "sockets": "llm",
}
_RANK = {"agent": 2, "llm": 1, "ai": 0}
_ATTR_COLUMNS = ("type", "name", "identifier", "source", "category", "confidence", "evidence", "running")


class FleetAIToolsAdapter:
    name = TOOL
    display = "Fleet ai_tools osquery table (fleetdm/fleet)"
    surfaces: Mapping[str, frozenset[str]] = {
        "endpoint": frozenset({"home"}),
        "runtime": frozenset({"live"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        if not binary:
            return "unknown"
        try:
            proc = subprocess.run(
                [binary, "-version"], capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"unknown ({exc})"
        return proc.stdout.strip() or "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        home = case.home or work
        return [Invocation(argv=(env.binary(TOOL) or TOOL,), cwd=work, env=base_env(home, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="fleet-ai-tools did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="fleet-ai-tools timed out")
        if run.code != 0:
            return AdapterResult(status="error", note=f"fleet-ai-tools exit {run.code}: {tail(run.stderr)}")
        try:
            data = json.loads(run.stdout or "[]")
        except json.JSONDecodeError as exc:
            return AdapterResult(status="error", note=f"fleet-ai-tools output is not JSON: {exc}")
        if not isinstance(data, list):
            return AdapterResult(status="error", note="fleet-ai-tools output is not a JSON array")
        rows = [row for row in data if isinstance(row, dict)]
        if case.surface == "runtime":
            entities = _process_entities(rows)
        else:
            entities = _artifact_entities(rows, case.home or work)
        raw = {"rows": [_slim(r) for r in rows[:400]]}
        return AdapterResult(status="ok", entities=entities, raw=raw)


def _stronger(current: Entity | None, label: str) -> bool:
    return current is None or _RANK.get(label, 0) > _RANK.get(current.label, 0)


def _attributes(row: dict[str, Any]) -> dict[str, Any]:
    return {column: str(row.get(column) or "") for column in _ATTR_COLUMNS}


def _artifact_entities(rows: list[dict[str, Any]], home: Path) -> list[Entity]:
    entities: dict[str, Entity] = {}
    for row in rows:
        label = HOME_LABELS.get(str(row.get("type") or ""))
        path = row.get("path")
        if label is None or not isinstance(path, str) or not path:
            continue
        key = relative_artifact(path, home)
        if key is None:
            continue
        if _stronger(entities.get(key), label):
            entities[key] = Entity(kind="artifact", key=key, label=label, attributes=_attributes(row))
    return list(entities.values())


def _process_entities(rows: list[dict[str, Any]]) -> list[Entity]:
    entities: dict[str, Entity] = {}
    for row in rows:
        row_type = str(row.get("type") or "")
        label = PROCESS_LABELS.get(row_type)
        pid = _pid(row.get("pid"))
        if label is None or pid <= 0:
            continue
        if row_type == "sockets" and str(row.get("category") or "").startswith("mcp"):
            label = "agent"
        key = f"process:{pid}"
        if _stronger(entities.get(key), label):
            attributes = _attributes(row)
            attributes["path"] = str(row.get("path") or "")
            entities[key] = Entity(kind="process", key=key, label=label, attributes=attributes)
    return list(entities.values())


def _pid(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _slim(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in {"detail", "sha256"} and v not in ("", None)}


ADAPTER = FleetAIToolsAdapter()
