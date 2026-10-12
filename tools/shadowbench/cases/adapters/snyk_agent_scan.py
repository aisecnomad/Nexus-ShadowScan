"""Snyk Agent Scan on the endpoint/home surface.

CLI (measured against snyk-agent-scan 0.6.8, PyPI ``snyk-agent-scan``)::

    snyk-agent-scan inspect --json --storage-file <work>/agent-scan-state --server-timeout 2

run with ``HOME=<case home>``, the contract's minimal environment and an
empty stdin. ``inspect`` auto-discovers the well-known client configurations
under ``$HOME`` (Claude Code ``.claude.json`` and its ``projects.*`` blocks,
Claude Desktop ``.config/Claude/claude_desktop_config.json`` on Linux, Cursor
``.cursor/mcp.json``, VS Code ``.config/Code/User/mcp.json``, Windsurf
``.codeium/windsurf/mcp_config.json``, Gemini CLI ``.gemini/settings.json``,
Codex ``.codex/config.toml``, Kiro, ...), parses every MCP server and every
skill directory, then asks on stderr for consent before contacting a server.
EOF on stdin declines every prompt, so no server subprocess is started and no
remote server is connected; without a push key nothing is uploaded. There is
no ``--version`` flag; the version comes from the installed distribution.

Exit code 0 is a completed inspection. Stdout is one JSON object keyed by
client directory::

    {"<home>/.cursor": {"client": "cursor", "path": "...",
                        "servers": [{"name", "config_path", "server", "signature", "error"}],
                        "skills": [{"name", "installation_path", "files": [{"path", "content"}]}],
                        "error": null}, ...}

Declined servers carry ``error.category == "user_declined"`` and still count:
the tool read them from the configuration.

Detection rule: every server maps to ``artifact:<config_path relative to the
home>`` and every skill to ``artifact:<installation_path>/SKILL.md`` (the
directory when the skill lists no SKILL.md), label ``agent``. A Claude Code
server whose ``config_path`` is a project directory (an inline
``projects.<dir>.mcpServers`` block) maps to ``artifact:.claude.json``, the
file it was read from. Paths outside the home (system-managed configs, project
``.mcp.json`` files elsewhere) are dropped. The decoy ``.minecraft/mcp.json``
is not a known client location and is not reported; ``.claude/agents/*.md``
subagents and ``.claude/settings.json`` are not reported by this version.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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

BIN = "snyk-agent-scan"
DISTRIBUTION = "snyk-agent-scan"
RAW_LIMIT = 200_000


def _distribution_version(binary: str, distribution: str) -> str:
    """Ask the interpreter next to the console script for the installed distribution version."""
    python = Path(binary).parent / "python"
    if not python.exists():
        return "unknown"
    code = f"import importlib.metadata as m; print(m.version({distribution!r}))"
    try:
        proc = subprocess.run(
            [str(python), "-I", "-c", code], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = proc.stdout.strip()
    return text if proc.returncode == 0 and text else "unknown"


def _json_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    if start < 0:
        return None
    try:
        doc = json.loads(text[start:])
    except json.JSONDecodeError:
        return None
    return doc if isinstance(doc, dict) else None


class SnykAgentScan:
    name = "snyk-agent-scan"
    display = "Snyk Agent Scan"
    surfaces: Mapping[str, frozenset[str]] = {"endpoint": frozenset({"home"})}

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
        return _distribution_version(binary, DISTRIBUTION) if binary else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        if case.home is None:
            return []
        binary = env.binary(BIN) or BIN
        argv = (
            binary,
            "inspect",
            "--json",
            "--storage-file",
            str(work / "agent-scan-state"),
            "--server-timeout",
            "2",
        )
        # An empty stdin answers every consent prompt with EOF (= decline): no server is contacted.
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home, work), timeout=300, stdin="")]

    @staticmethod
    def _server_key(config_path: str, client: str, home: Path) -> str | None:
        if client == "claude code" and not config_path.endswith(".json"):
            # projects.<dir>.mcpServers inline in ~/.claude.json: the key is the project directory.
            return "artifact:.claude.json"
        return relative_artifact(config_path, home)

    @staticmethod
    def _skill_key(skill: dict[str, Any], home: Path) -> str | None:
        install = skill.get("installation_path")
        if not isinstance(install, str) or not install:
            return None
        files = skill.get("files")
        names = {f.get("path") for f in files if isinstance(f, dict)} if isinstance(files, list) else set()
        key = relative_artifact(install, home)
        if key is None:
            return None
        return f"{key}/SKILL.md" if "SKILL.md" in names else key

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if case.home is None:
            return AdapterResult("error", note="case has no home directory")
        if not runs:
            return AdapterResult("error", note="tool was not run")
        run = runs[0]
        raw = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult("error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        doc = _json_object(run.stdout)
        if run.code != 0 or doc is None:
            return AdapterResult("error", note=f"exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw)
        found: dict[str, Entity] = {}
        servers = skills = dropped = 0
        for block in doc.values():
            if not isinstance(block, dict):
                continue
            client = str(block.get("client") or "")
            for server in block.get("servers") or []:
                if not isinstance(server, dict):
                    continue
                servers += 1
                config_path = server.get("config_path")
                key = (
                    self._server_key(config_path, client, case.home) if isinstance(config_path, str) else None
                )
                if key is None:
                    dropped += 1
                    continue
                entity = found.get(key)
                names = list(entity.attributes.get("servers", [])) if entity else []
                names.append(str(server.get("name")))
                found[key] = Entity("mcp-server", key, "agent", {"client": client, "servers": names})
            for skill in block.get("skills") or []:
                if not isinstance(skill, dict):
                    continue
                key = self._skill_key(skill, case.home)
                if key is None:
                    dropped += 1
                    continue
                skills += 1
                if key not in found:
                    found[key] = Entity("skill", key, "agent", {"name": str(skill.get("name"))})
        note = f"clients={len(doc)} servers={servers} skill_entries={skills} outside_home={dropped}"
        return AdapterResult("ok", entities=list(found.values()), note=note, raw=raw)


ADAPTER = SnykAgentScan()
