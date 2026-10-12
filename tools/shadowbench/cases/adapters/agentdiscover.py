"""DefendAI AgentDiscover on the endpoint/home and code/checkout surfaces.

CLI (measured against agentdiscover 2.9.5, PyPI ``agentdiscover``)::

    agentdiscover scan-all <root> --output <work>/agentdiscover --skip-layers 2,3,4,5 \\
        --duration 1 --format json

run with ``COLUMNS=100000`` on top of the contract's minimal environment,
``HOME=<case home>`` for endpoint cases and ``HOME=<work>`` for code cases.
``scan-all`` runs Layer 1 (the static scan ``agentdiscover scan`` performs,
written to ``<output>/layer1_code.sarif`` when the tree has Python or
JavaScript files), the MCP configuration detector and the correlation step,
and ``--format json`` prints the final report to stdout; layers 2-5 (network
monitor, Tetragon, osquery, CloudTrail) are skipped. The report goes through a
``rich`` console that soft-wraps at 80 columns when stdout is not a terminal,
which breaks the JSON mid-string, hence ``COLUMNS``. The tool runs
``npm config get prefix`` to find global CLIs (no network) and writes
``.npm/_logs`` into ``$HOME``. ``agentdiscover --version`` prints
``AgentDiscover v2.9.5``. The earlier two-step ``scan --format sarif`` +
``audit --skip-layers 2,3,4,5`` form still works but ``audit`` only writes
server names into ``mcp-report.md`` without the client or file they came
from; ``scan-all --format json`` carries that.

Report shape (stdout, after banner lines)::

    {"summary": {"total_agents", ...}, "inventory": {"confirmed"|"unknown"|"zombie"|"ghost"|
     "shadow_ai_usage": [{"agent_id": "<file>:<line>", "code_file", "framework", "rule_id", ...}]},
     "mcp": {"servers": [{"server_name", "client", "package", "source"?, ...}], ...},
     "scan_path": "<root>"}

MCP detection (``mcp_detector.MCP_CONFIG_LOCATIONS``) reads, per client, the
first existing file of a fixed list: Claude Desktop
``~/Library/Application Support/Claude/claude_desktop_config.json``,
``~/AppData/Roaming/Claude/...``, ``~/.config/claude/...`` (lower-case, so
``~/.config/Claude`` on Linux is missed); Cursor ``~/.cursor/mcp.json``;
Gemini CLI ``~/.gemini/settings.json`` or ``<root>/.gemini/settings.json``;
OpenAI Codex ``~/.codex/config.toml`` or ``<root>/.codex/config.toml``; VS
Code ``<root>/.vscode/mcp.json`` plus macOS/Windows user paths (not
``~/.config/Code/User/mcp.json``); Project MCP ``<root>/mcp.json``,
``<root>/.mcp/config.json``, ``<root>/.mcp.json``; Windsurf, Continue and Zed
settings on macOS; and ``<root>/.cursor/mcp.json`` as "Generic Project MCP".
``~`` expands with ``$HOME``, so repo scans run with an empty home. Claude
Code ``~/.claude.json``, skills and subagents are not read; the decoy
``.minecraft/mcp.json`` is not a listed location. The report names the
``client`` but not the file, so the adapter replays the same table (first
existing candidate whose server map is non-empty) to attribute each server to
its file. Static rules: DAI001 AutoGen agent, DAI002 CrewAI agent, DAI003
LangChain/LangGraph agent, DAI004 unmanaged LLM client (OpenAI, Anthropic,
..., also JavaScript), DAI008 declared model identifier, DAI009 generation
parameters.

Detection rules:

* endpoint/home: each MCP server maps to ``artifact:<config file relative to
  home>`` (label ``agent``); each SARIF result and inventory agent maps to
  ``artifact:<file relative to home>`` with label ``agent`` for DAI001-003
  and ``llm`` for DAI004/DAI008/DAI009 (``agent`` wins when both hit a file).
* code/checkout: MCP servers map to ``taxonomy.facts_for_config_path`` of the
  attributed file (``.mcp.json`` -> ``mcp-client-config:claude-code``) and
  servers taken from ``package.json``/``requirements.txt`` to
  ``taxonomy.facts_for``; SARIF messages and inventory frameworks map through
  ``taxonomy.facts_from_name`` ("CrewAI Agent detected" -> ``framework:crewai``,
  "Unmanaged OpenAI client detected" -> ``provider:openai``). ``provider:*``
  facts are labeled ``llm``, everything else ``agent``. A hit that maps to no
  fact is dropped and listed as ``unmapped`` in the note: code truth holds
  only taxonomy facts, so any other key could never match (the ShadowScan
  adapter drops its unmappable findings the same way).

``version()`` runs ``agentdiscover --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout) unless ``tools.json`` pins a version.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
from tools.shadowbench.cases.adapters._probe import cli_version
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

BIN = "agentdiscover"
RAW_LIMIT = 200_000
OUTPUT_DIR = "agentdiscover"
AGENT_RULES = frozenset({"DAI001", "DAI002", "DAI003"})

# mcp_detector.MCP_CONFIG_LOCATIONS of agentdiscover 2.9.5: client -> (candidate paths, format, key).
# "~/" paths expand with HOME; the others are relative to the scanned root.
CLIENT_CONFIGS: dict[str, tuple[tuple[str, ...], str, str]] = {
    "Claude Desktop": (
        (
            "~/Library/Application Support/Claude/claude_desktop_config.json",
            "~/AppData/Roaming/Claude/claude_desktop_config.json",
            "~/.config/claude/claude_desktop_config.json",
        ),
        "json",
        "mcpServers",
    ),
    "Cursor": (
        (
            "~/.cursor/mcp.json",
            "~/Library/Application Support/Cursor/mcp.json",
            "~/AppData/Roaming/Cursor/mcp.json",
        ),
        "json",
        "mcpServers",
    ),
    "Gemini CLI": (("~/.gemini/settings.json", ".gemini/settings.json"), "json", "mcpServers"),
    "OpenAI Codex": (("~/.codex/config.toml", ".codex/config.toml"), "toml", "mcp_servers"),
    "VS Code Copilot": (
        (
            ".vscode/mcp.json",
            "~/Library/Application Support/Code/User/mcp.json",
            "~/AppData/Roaming/Code/User/mcp.json",
        ),
        "json",
        "servers",
    ),
    "Project MCP": (("mcp.json", ".mcp/config.json", ".mcp.json"), "json", "mcpServers"),
    "Windsurf": (("~/Library/Application Support/Windsurf/User/settings.json",), "json", "mcpServers"),
    "Continue.dev": (("~/.continue/config.json",), "json", "mcpServers"),
    "Zed": (("~/.config/zed/settings.json",), "json", "mcpServers"),
    "Generic Project MCP": ((".cursor/mcp.json",), "json", "mcpServers"),
}
MANIFEST_SOURCES = {"package.json": "npm", "requirements.txt": "pypi"}


def _json_report(text: str) -> dict[str, Any] | None:
    """The report object printed after the banner lines."""
    for match in re.finditer(r"^\{", text, flags=re.MULTILINE):
        try:
            doc, _end = json.JSONDecoder().raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and "mcp" in doc and "inventory" in doc:
            return doc
    return None


def _server_map(path: Path, fmt: str, key: str) -> dict[str, Any] | None:
    """The server block the tool would read from ``path``; None when unreadable or absent."""
    try:
        if fmt == "toml":
            data: Any = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
        else:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return None
    block = data.get(key) if isinstance(data, dict) else None
    return block if isinstance(block, dict) else None


def _client_config(client: str, home: Path, root: Path) -> Path | None:
    """Replay the tool's lookup: the first candidate file for ``client`` with a non-empty server map."""
    spec = CLIENT_CONFIGS.get(client)
    if spec is None:
        return None
    candidates, fmt, key = spec
    first_existing: Path | None = None
    for candidate in candidates:
        path = home / candidate[2:] if candidate.startswith("~/") else root / candidate
        if not path.is_file():
            continue
        first_existing = first_existing or path
        if _server_map(path, fmt, key):
            return path
    return first_existing


def _sarif_results(path: Path) -> list[tuple[str, str, str]] | None:
    """(rule id, message, relative uri) per result; None when the file is unreadable."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    out: list[tuple[str, str, str]] = []
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule = str(result.get("ruleId") or "")
            message = result.get("message")
            text = str(message.get("text") or "") if isinstance(message, dict) else ""
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") if isinstance(location, dict) else None
                artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
                uri = artifact.get("uri") if isinstance(artifact, dict) else None
                if isinstance(uri, str) and uri:
                    out.append((rule, text, uri))
    return out


def _rule_label(rule_id: str) -> str:
    return "agent" if rule_id in AGENT_RULES else "llm"


def _fact_label(fact: str) -> str:
    return "llm" if fact.startswith("provider:") else "agent"


class _Collector:
    """Entities keyed once; attributes merge and ``agent`` beats ``llm`` when a key is hit twice."""

    def __init__(self) -> None:
        self.found: dict[str, Entity] = {}

    def add(self, kind: str, key: str, label: str, **attributes: Any) -> None:
        current = self.found.get(key)
        if current is None:
            self.found[key] = Entity(kind, key, label, attributes)
            return
        upgraded = current.label != "agent" and label == "agent"
        winner_kind = kind if upgraded or current.label == label else current.kind
        winner_label = "agent" if "agent" in (current.label, label) else current.label
        self.found[key] = Entity(winner_kind, key, winner_label, {**current.attributes, **attributes})

    def entities(self) -> list[Entity]:
        return list(self.found.values())


class AgentDiscover:
    name = "agentdiscover"
    display = "AgentDiscover Scanner (DefendAI)"
    surfaces: Mapping[str, frozenset[str]] = {
        "endpoint": frozenset({"home"}),
        "code": frozenset({"checkout"}),
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
        return cli_version(binary) if binary else "unknown"

    @staticmethod
    def _root(case: MaterializedCase) -> Path | None:
        return case.home if case.surface == "endpoint" else case.inputs / "repo"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        root = self._root(case)
        if root is None:
            return []
        binary = env.binary(BIN) or BIN
        argv = (
            binary,
            "scan-all",
            str(root),
            "--output",
            str(work / OUTPUT_DIR),
            "--skip-layers",
            "2,3,4,5",
            "--duration",
            "1",
            "--format",
            "json",
        )
        # COLUMNS keeps the rich console from wrapping (and breaking) the JSON report.
        environ = {**base_env(case.home or work, work), "COLUMNS": "100000"}
        return [Invocation(argv=argv, cwd=work, env=environ, timeout=600)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        root = self._root(case)
        if root is None:
            return AdapterResult("error", note="case has no home directory")
        if not runs:
            return AdapterResult("error", note="tool was not run")
        run = runs[0]
        raw: dict[str, Any] = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult("error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        report = _json_report(run.stdout)
        if run.code != 0 or report is None:
            return AdapterResult("error", note=f"exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw)
        sarif_path = work / OUTPUT_DIR / "layer1_code.sarif"
        results: list[tuple[str, str, str]] = []
        if sarif_path.exists():
            parsed = _sarif_results(sarif_path)
            if parsed is None:
                return AdapterResult("error", note="layer1_code.sarif is unreadable", raw=raw)
            results = parsed
            raw["layer1_code.sarif"] = sarif_path.read_text(encoding="utf-8")[:RAW_LIMIT]
        elif (report.get("summary") or {}).get("detection_coverage", {}).get("layer1"):
            return AdapterResult("error", note="layer1 reported findings but wrote no SARIF", raw=raw)
        home = case.home if case.home is not None else work
        servers = [s for s in (report.get("mcp") or {}).get("servers") or [] if isinstance(s, dict)]
        agents = [
            a
            for group in (report.get("inventory") or {}).values()
            if isinstance(group, list)
            for a in group
            if isinstance(a, dict)
        ]
        if case.surface == "endpoint":
            return self._home_artifacts(servers, results, agents, home, root, raw)
        return self._code_facts(servers, results, agents, home, root, raw)

    @staticmethod
    def _server_path(server: dict[str, Any], home: Path, root: Path) -> Path | None:
        source = server.get("source")
        if isinstance(source, str) and source in MANIFEST_SOURCES:
            return root / source
        client = server.get("client")
        return _client_config(str(client), home, root) if isinstance(client, str) else None

    def _home_artifacts(
        self,
        servers: list[dict[str, Any]],
        results: list[tuple[str, str, str]],
        agents: list[dict[str, Any]],
        home: Path,
        root: Path,
        raw: dict[str, Any],
    ) -> AdapterResult:
        out = _Collector()
        unattributed: list[str] = []
        for server in servers:
            path = self._server_path(server, home, root)
            key = relative_artifact(str(path), root) if path else None
            if key is None:
                unattributed.append(str(server.get("server_name")))
                continue
            names = list(out.found[key].attributes.get("servers", [])) if key in out.found else []
            name = str(server.get("server_name"))
            if name not in names:
                names.append(name)
            out.add("mcp-server", key, "agent", client=str(server.get("client")), servers=names)
        for rule, message, uri in results:
            key = relative_artifact(str(root / uri), root)
            if key:
                out.add("source-file", key, _rule_label(rule), rule=rule, message=message[:120])
        for agent in agents:
            code_file = agent.get("code_file")
            if isinstance(code_file, str) and code_file:
                key = relative_artifact(str(root / code_file), root)
                if key:
                    rule = str(agent.get("rule_id") or "")
                    out.add("agent", key, _rule_label(rule), framework=str(agent.get("framework")), rule=rule)
        note = f"servers={len(servers)} sarif={len(results)} agents={len(agents)}"
        if unattributed:
            note += f" unattributed_servers={unattributed[:10]}"
        return AdapterResult("ok", entities=out.entities(), note=note, raw=raw)

    def _code_facts(
        self,
        servers: list[dict[str, Any]],
        results: list[tuple[str, str, str]],
        agents: list[dict[str, Any]],
        home: Path,
        root: Path,
        raw: dict[str, Any],
    ) -> AdapterResult:
        out = _Collector()
        unmapped: list[str] = []

        def emit(facts: set[str], rel: str, **attrs: Any) -> None:
            if not facts:
                unmapped.append(rel)  # dropped: an artifact key never matches code truth
                return
            for fact in sorted(facts):
                out.add("fact", fact, _fact_label(fact), path=rel, **attrs)

        for server in servers:
            name = str(server.get("server_name") or "")
            source = server.get("source")
            path = self._server_path(server, home, root)
            key = relative_artifact(str(path), root) if path else None
            if key is None:
                unmapped.append(f"server:{name}")
                continue
            rel = key[len("artifact:") :]
            if isinstance(source, str) and source in MANIFEST_SOURCES:
                facts = set(taxonomy.facts_for(MANIFEST_SOURCES[source], name))
            else:
                facts = set(taxonomy.facts_for_config_path(rel))
            emit(facts, rel, server=name, client=str(server.get("client")))
        for rule, message, uri in results:
            emit(set(taxonomy.facts_from_name(message)), uri, rule=rule, message=message[:120])
        for agent in agents:
            code_file = agent.get("code_file")
            framework = agent.get("framework")
            if isinstance(code_file, str) and isinstance(framework, str):
                facts = set(taxonomy.facts_from_name(framework))
                # A framework name that maps nowhere ("Shadow AI") is already covered by its SARIF hit.
                if facts:
                    emit(facts, code_file, framework=framework, rule=str(agent.get("rule_id") or ""))
        note = f"servers={len(servers)} sarif={len(results)} agents={len(agents)}"
        note += f" facts={sum(e.kind == 'fact' for e in out.entities())}"
        if unmapped:
            note += f" unmapped={sorted(set(unmapped))[:10]}"
        return AdapterResult("ok", entities=out.entities(), note=note, raw=raw)


ADAPTER = AgentDiscover()
