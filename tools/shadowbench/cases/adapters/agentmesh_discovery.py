"""Microsoft Agent Governance Toolkit ``agent-discovery`` on three surfaces.

CLI (measured against agentmesh-discovery 5.0.0 from PyPI, whose console
script ``agent-discovery --version`` reports ``0.1.0``)::

    agent-discovery scan -s config -p <root> -o json --storage <work>/inventory.json   # endpoint, code
    agent-discovery scan -s process -o json --storage <work>/inventory.json            # runtime/live

``scan`` accepts ``-s/--scanner {process,config,github}`` (repeatable),
``-p/--paths``, ``-o/--output {table,json}`` and ``--storage``. Only the
``github`` scanner needs network; ``config`` and ``process`` run offline.
``--storage`` must be given or the tool writes ``~/.agent-discovery/inventory.json``
into the case home, and a fresh file per run keeps earlier runs out of the
inventory. Exit code is 0 even when nothing is found. Stdout carries rich
banner lines ("Agent Discovery Scan", "Running config scanner...", "Found N
agents") followed by the JSON inventory array and an "Inventory saved to"
trailer, so the array is extracted with ``raw_decode`` from the first line
that starts with ``[``. Each element has ``agent_type``, ``name``,
``evidence[].source`` (absolute path or ``PID <n>``), ``tags`` and
``confidence``.

Config scanner (``agent_discovery/scanners/config.py``): walks the root
(skipping ``.git``, ``node_modules``, virtualenvs) for files named
``agentmesh.yaml|yml``, ``.agentmesh/config.yaml``, ``agent-governance.yaml``,
``crewai.yaml|yml``, ``mcp.json``, ``mcp-config.json``, ``.mcp/config.json``,
``claude_desktop_config.json``, ``.copilot-setup-steps.yml`` and
``copilot-setup-steps.yml``, and greps ``Dockerfile`` and
``docker-compose.yml|yaml`` for ``langchain|langgraph``, ``crewai``,
``autogen``, ``agentmesh``, ``mcp[_-]server`` and ``semantic[_-]kernel``. It
matches by filename only: ``.cursor/mcp.json`` and the decoy
``.minecraft/mcp.json`` are both reported as ``mcp-server``; ``.claude.json``,
``.gemini/settings.json``, ``.codex/config.toml``,
``.codeium/windsurf/mcp_config.json``, skills and subagents are not. Note that
``.mcp.json`` is reported through the ``mcp.json`` suffix rule.

Process scanner (``scanners/process.py``): runs ``ps aux`` and matches each
command line against ``langchain|langgraph|langserve``, ``crewai|crew\\.run``,
``autogen|groupchat``, ``openai.*agents|swarm``, ``semantic.kernel|sk_agent``,
``agentmesh|agent.os|agent.governance``, ``mcp.server|mcp_server|model.context.protocol``,
``llamaindex|llama.index``, ``haystack``, ``pydantic.ai|pydanticai`` and
``google.*adk|genai.*agent``. ``python -m crewai run`` matches;
``npx -y @modelcontextprotocol/server-github`` does not (``modelcontextprotocol``
has no separator for ``model.context.protocol``). The scanner reports its own
process when the install path contains ``agentmesh``.

Detection rules:

* endpoint/home: each config hit's ``evidence[].source`` (falling back to
  ``tags.config_file`` / ``tags.docker_file``) becomes
  ``artifact:<path relative to home>``, label ``agent``.
* code/checkout: the relative path is mapped onto discovery-benchmark facts
  with ``taxonomy.facts_for_config_path`` (``.mcp.json`` ->
  ``mcp-client-config:claude-code``) and, when the path maps nowhere, the
  ``agent_type`` with ``taxonomy.facts_from_name`` (``crewai.yaml`` ->
  ``framework:crewai``, Compose ``langchain`` -> ``framework:langchain``),
  label ``agent``; a hit that maps to no fact
  (``agentmesh.yaml`` -> ``agt``, ``copilot-setup-steps.yml``), or names no
  file in the checkout, is dropped, counted in the row's ``out_of_taxonomy``
  and, with its file, listed as ``unmapped_files`` in the note: code truth
  holds only taxonomy facts, so any other key could never match, but the
  scorer still counts the hit as an alarm on a negative case (the ShadowScan
  adapter treats its unmappable findings the same way).
* runtime/live: each process hit becomes ``process:<tags.pid>``, label
  ``agent``; the tool's own ``agent-discovery scan`` process is dropped.

Fail closed: stdout without the inventory array, or an array entry that is not
an object, is an error, never an empty inventory.

``version()`` asks the venv interpreter for the distribution version and runs
``agent-discovery --version``, both through ``_probe`` (scrubbed environment,
throwaway home, timeout), unless ``tools.json`` pins a version.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
from tools.shadowbench.cases.adapters._probe import cli_version, distribution_version
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

BIN = "agentmesh-discovery"
DISTRIBUTION = "agentmesh-discovery"
RAW_LIMIT = 200_000
_SELF = "agent-discovery"


def _json_array(text: str) -> list[Any] | None:
    """The inventory array printed after the banner lines (and before the storage trailer)."""
    for match in re.finditer(r"^\[", text, flags=re.MULTILINE):
        try:
            doc, _end = json.JSONDecoder().raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(doc, list):
            return doc
    return None


def _source_path(agent: dict[str, Any]) -> str | None:
    for evidence in agent.get("evidence") or []:
        if isinstance(evidence, dict):
            source = evidence.get("source")
            if isinstance(source, str) and source and not source.startswith("PID "):
                return source
    tags_value = agent.get("tags")
    tags: dict[str, Any] = tags_value if isinstance(tags_value, dict) else {}
    for key in ("config_file", "docker_file"):
        value = tags.get(key)
        if isinstance(value, str) and value:
            root = tags.get("root")
            return str(Path(root) / value) if isinstance(root, str) and root else value
    return None


class AgentMeshDiscovery:
    name = "agentmesh-discovery"
    display = "Agent Discovery (Microsoft Agent Governance Toolkit)"
    surfaces: Mapping[str, frozenset[str]] = {
        "endpoint": frozenset({"home"}),
        "code": frozenset({"checkout"}),
        "runtime": frozenset({"live"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        binary = env.binary(BIN)
        if not binary:
            return f"no 'bin' configured for {BIN} in tools.json"
        if not Path(binary).exists():
            return f"{binary} does not exist"
        return None

    def version(self, env: ToolEnv) -> str:
        pinned = env.tool(BIN).get("version")
        if isinstance(pinned, str) and pinned:
            return pinned
        binary = env.binary(BIN)
        if not binary:
            return "unknown"
        dist = distribution_version(binary, DISTRIBUTION)
        cli = cli_version(binary)
        return f"{dist} (cli {cli})" if dist != "unknown" else cli

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        binary = env.binary(BIN) or BIN
        storage = str(work / "inventory.json")
        if case.surface == "runtime":
            argv: tuple[str, ...] = (binary, "scan", "-s", "process", "-o", "json", "--storage", storage)
        else:
            root = case.home if case.surface == "endpoint" else case.inputs / "repo"
            if root is None:
                return []
            argv = (binary, "scan", "-s", "config", "-p", str(root), "-o", "json", "--storage", storage)
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult("error", note="tool was not run")
        run = runs[0]
        raw = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult("error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        agents = _json_array(run.stdout)
        if run.code != 0 or agents is None:
            return AdapterResult("error", note=f"exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw)
        if not all(isinstance(a, dict) for a in agents):
            return AdapterResult("error", note="inventory array has an entry that is not an object", raw=raw)
        records: list[dict[str, Any]] = agents
        if case.surface == "runtime":
            return self._processes(records, raw)
        if case.surface == "endpoint":
            if case.home is None:
                return AdapterResult("error", note="case has no home directory", raw=raw)
            return self._home_artifacts(records, case.home, raw)
        return self._code_facts(records, case.inputs / "repo", raw)

    @staticmethod
    def _home_artifacts(records: list[dict[str, Any]], home: Path, raw: dict[str, Any]) -> AdapterResult:
        found: dict[str, Entity] = {}
        outside = 0
        for agent in records:
            source = _source_path(agent)
            key = relative_artifact(source, home) if source else None
            if key is None:
                outside += 1
                continue
            if key not in found:
                attrs = {"agent_type": str(agent.get("agent_type")), "confidence": agent.get("confidence")}
                found[key] = Entity("config", key, "agent", attrs)
        note = f"agents={len(records)} outside_home={outside}"
        return AdapterResult("ok", entities=list(found.values()), note=note, raw=raw)

    @staticmethod
    def _code_facts(records: list[dict[str, Any]], repo: Path, raw: dict[str, Any]) -> AdapterResult:
        found: dict[str, Entity] = {}
        unmapped: list[str] = []
        unplaced = 0
        for agent in records:
            source = _source_path(agent)
            key = relative_artifact(source, repo) if source else None
            if key is None:
                unplaced += 1
                continue
            rel = key[len("artifact:") :]
            agent_type = str(agent.get("agent_type") or "")
            # The path decides (".mcp.json" -> claude-code config); the tool's type name only fills in
            # for files the path table does not know (crewai.yaml, a Compose file naming langchain).
            facts = set(taxonomy.facts_for_config_path(rel)) or set(taxonomy.facts_from_name(agent_type))
            if not facts:
                unmapped.append(rel)  # dropped: an artifact key never matches code truth
                continue
            for fact in sorted(facts):
                attrs = {"path": rel, "agent_type": agent_type}
                found.setdefault(fact, Entity("fact", fact, "agent", attrs))
        note = f"agents={len(records)} facts={sum(e.kind == 'fact' for e in found.values())}"
        if unmapped:
            note += f" unmapped_files={sorted(set(unmapped))[:10]}"
        if unplaced:
            note += f" outside_checkout={unplaced}"
        return AdapterResult(
            "ok",
            entities=list(found.values()),
            note=note,
            raw=raw,
            out_of_taxonomy=len(set(unmapped)) + unplaced,
        )

    @staticmethod
    def _processes(records: list[dict[str, Any]], raw: dict[str, Any]) -> AdapterResult:
        found: dict[str, Entity] = {}
        dropped_self = 0
        for agent in records:
            tags_value = agent.get("tags")
            tags: dict[str, Any] = tags_value if isinstance(tags_value, dict) else {}
            pid = tags.get("pid")
            cmdline = ""
            for evidence in agent.get("evidence") or []:
                data = evidence.get("raw_data") if isinstance(evidence, dict) else None
                if isinstance(data, dict) and isinstance(data.get("cmdline_redacted"), str):
                    cmdline = data["cmdline_redacted"]
            if not isinstance(pid, str | int) or not str(pid).isdigit():
                continue
            if _SELF in cmdline:
                dropped_self += 1
                continue
            key = f"process:{pid}"
            attrs = {"agent_type": str(agent.get("agent_type")), "cmdline": cmdline[:200]}
            found.setdefault(key, Entity("process", key, "agent", attrs))
        note = f"agents={len(records)} self={dropped_self}"
        return AdapterResult("ok", entities=list(found.values()), note=note, raw=raw)


ADAPTER = AgentMeshDiscovery()
