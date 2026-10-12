"""SafeDep vet ``ai discover`` on endpoint/home (system scope) and code/checkout (project scope).

Install (vet v1.20.0 needs cgo for go-tree-sitter; its go.mod says ``go 1.26.2``,
so Go 1.24 fetches the go1.26.9 toolchain through the module proxy)::

    CGO_ENABLED=1 GOBIN=<tool_root>/bin go install github.com/safedep/vet@v1.20.0

Invocations (``VET_DISABLE_TELEMETRY=true``; ``HOME`` is the case home)::

    vet ai discover --scope system --report-json <work>/vet.json --silent --no-banner
    vet ai discover --scope project -D <inputs/repo> --report-json <work>/vet.json --silent --no-banner

vet resolves the user home with ``os.UserHomeDir`` (``$HOME``) and, with HOME
pointed at a probe home, reported nothing from the real user's home. It needs
no network (it prints one line, "SafeDep cloud sync available...", to stderr),
exits 0 whether or not it finds anything, and writes ``null`` or ``[]`` to the
report when it finds nothing.

Report: a JSON array of ``pkg/inventory.Item`` objects. ``Kind``: 1 MCP server,
2 coding agent, 3 AI IDE extension, 4 agent CLI binary, 5 project config, 6
browser extension, 7 non-AI IDE extension, 8 agent plugin, 9 agent skill.
``Scope``: 1 system, 2 project. ``ConfigPath`` is the absolute path of the file
or directory the item came from (``~/.claude.json``, ``~/.cursor/mcp.json``,
``~/.codex/config.toml``, ``~/.gemini/settings.json``, ``~/.config/Code/User/mcp.json``,
``~/.claude/settings.json``, or the agent's directory such as ``~/.cursor``);
``Agent.InstructionFiles`` lists instruction files (``CLAUDE.md``,
``.cursorrules``); ``MCPServer`` holds the server entry. vet reads the top-level
``mcpServers`` of ``.claude.json`` but not the per-project ``projects.*.mcpServers``.

Mapping, endpoint/home: ``ConfigPath`` and each ``Agent.InstructionFiles`` entry
under the case home becomes ``artifact:<path relative to home>``. Kinds 1, 2, 4,
5, 8 and 9 are labelled ``agent`` (MCP server entries, coding agents and their
configuration, agent CLIs, plugins, skills); kinds 3 and 6 ``llm`` (AI editor
or browser extensions without agent evidence); kind 7 is skipped; an unknown
kind is ``ai``. A path reported under several kinds keeps the strongest label.

Mapping, code/checkout: each reported path becomes the ``<category>:<value>``
facts ``tools.discovery_benchmark.taxonomy.facts_for_config_path`` assigns to its
repo-relative path (``.cursor/mcp.json`` -> ``mcp-client-config:cursor``,
``CLAUDE.md`` -> ``agent-config:claude-md``, ``.codex/config.toml`` ->
``mcp-client-config:codex`` and ``agent-config:codex``). An MCP server entry
whose path matches no rule yields ``mcp-client-config:generic``; a coding-agent
or project-config item without a matching rule yields ``agent-config:generic``.
Facts are entities of kind ``fact`` labelled ``agent`` for the
``mcp-client-config``, ``agent-config`` and ``a2a`` categories and ``llm`` otherwise.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
from tools.shadowbench.cases.contract import (
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

TOOL = "vet"
REPORT = "vet.json"

KIND_LABEL: Mapping[int, str] = {
    1: "agent",  # MCP server entry
    2: "agent",  # coding agent
    3: "llm",  # AI IDE extension
    4: "agent",  # agent CLI binary
    5: "agent",  # project config (instruction files)
    6: "llm",  # browser extension
    8: "agent",  # agent plugin
    9: "agent",  # agent skill
}
SKIP_KINDS = frozenset({7})  # non-AI IDE extension
AGENT_FACT_CATEGORIES = frozenset({"mcp-client-config", "agent-config", "a2a"})
_RANK = {"agent": 2, "llm": 1, "ai": 0}
_VERSION = re.compile(r"v\d+\.\d+\.\d+\S*")
_EMPTY_REPORTS = frozenset({"", "null", "[]"})


class VetAdapter:
    name = TOOL
    display = "SafeDep vet ai discover"
    surfaces: Mapping[str, frozenset[str]] = {
        "endpoint": frozenset({"home"}),
        "code": frozenset({"checkout"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        if not binary:
            return "unknown"
        try:
            proc = subprocess.run(
                [binary, "version", "--no-banner"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={"VET_DISABLE_TELEMETRY": "true", "HOME": "/nonexistent", "PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"unknown ({exc})"
        match = _VERSION.search(proc.stdout + proc.stderr)
        return match.group(0) if match else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        home = case.home or work
        binary = env.binary(TOOL) or TOOL
        environ = base_env(home, work)
        environ.update({"VET_DISABLE_TELEMETRY": "true", "VET_TELEMETRY": "false"})
        report = str(work / REPORT)
        argv: tuple[str, ...]
        if case.surface == "code":
            repo = case.inputs / "repo"
            argv = (binary, "ai", "discover", "--scope", "project", "-D", str(repo), "--report-json", report)
            cwd = repo
        else:
            argv = (binary, "ai", "discover", "--scope", "system", "--report-json", report)
            cwd = work
        return [Invocation(argv=(*argv, "--silent", "--no-banner"), cwd=cwd, env=environ, timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="vet did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="vet ai discover timed out")
        if run.code != 0:
            return AdapterResult(status="error", note=f"vet ai discover exit {run.code}: {tail(run.stderr)}")
        items, error = _load_items(work / REPORT)
        if error:
            return AdapterResult(status="error", note=error)
        if case.surface == "code":
            entities = _code_entities(items, case.inputs / "repo")
        else:
            entities = _home_entities(items, case.home or work)
        return AdapterResult(status="ok", entities=entities, raw={"items": items[:400]})


def _load_items(report: Path) -> tuple[list[dict[str, Any]], str]:
    if not report.exists():
        return [], ""  # vet writes no report when it finds nothing
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"cannot read {report.name}: {exc}"
    if text.strip() in _EMPTY_REPORTS:
        return [], ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"{report.name} is not JSON: {exc}"
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return [], f"{report.name} is not a JSON array"
    return [item for item in data if isinstance(item, dict)], ""


def _kind(item: dict[str, Any]) -> int:
    value = item.get("Kind", item.get("kind"))
    return value if isinstance(value, int) else -1


def _paths(item: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    config = item.get("ConfigPath") or item.get("config_path")
    if isinstance(config, str) and config:
        paths.append(config)
    agent = item.get("Agent") or item.get("agent")
    if isinstance(agent, dict):
        files = agent.get("InstructionFiles") or agent.get("instruction_files") or []
        paths.extend(f for f in files if isinstance(f, str) and f)
    return paths


def _stronger(current: Entity | None, label: str) -> bool:
    return current is None or _RANK.get(label, 0) > _RANK.get(current.label, 0)


def _home_entities(items: list[dict[str, Any]], home: Path) -> list[Entity]:
    entities: dict[str, Entity] = {}
    for item in items:
        kind = _kind(item)
        if kind in SKIP_KINDS:
            continue
        label = KIND_LABEL.get(kind, "ai")
        for path in _paths(item):
            key = relative_artifact(path, home)
            if key is None:
                continue
            if _stronger(entities.get(key), label):
                entities[key] = Entity(
                    kind="artifact",
                    key=key,
                    label=label,
                    attributes={
                        "vet_kind": kind,
                        "app": str(item.get("App") or item.get("app") or ""),
                        "name": str(item.get("Name") or item.get("name") or ""),
                    },
                )
    return list(entities.values())


def _code_entities(items: list[dict[str, Any]], repo: Path) -> list[Entity]:
    entities: dict[str, Entity] = {}
    for item in items:
        kind = _kind(item)
        if kind in SKIP_KINDS:
            continue
        facts: set[str] = set()
        for path in _paths(item):
            facts.update(taxonomy.facts_for_config_path(_repo_relative(path, repo)))
        if kind == 1 and not any(f.startswith("mcp-client-config:") for f in facts):
            facts.add("mcp-client-config:generic")
        elif kind in {2, 5} and not any(f.startswith("agent-config:") for f in facts):
            facts.add("agent-config:generic")
        for fact in facts:
            label = "agent" if taxonomy.category(fact) in AGENT_FACT_CATEGORIES else "llm"
            if _stronger(entities.get(fact), label):
                entities[fact] = Entity(
                    kind="fact",
                    key=fact,
                    label=label,
                    attributes={"vet_kind": kind, "app": str(item.get("App") or item.get("app") or "")},
                )
    return list(entities.values())


def _repo_relative(path: str, repo: Path) -> str:
    try:
        return Path(path).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return path.replace("\\", "/")


ADAPTER = VetAdapter()
