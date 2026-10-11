"""Cisco MCP Scanner on the endpoint/home surface.

CLI (measured against cisco-ai-mcp-scanner 4.8.6; the PyPI name is
``cisco-ai-mcp-scanner``, the console script ``mcp-scanner``)::

    mcp-scanner --analyzers yara --format raw --log-level debug known-configs

run with ``HOME=<case home>``, the contract's minimal environment and
``MCP_SCANNER_STDIO_TIMEOUT=2``. ``known-configs`` (the subcommand form of the
older ``--scan-known-configs`` flag, which still works) reads the well-known
client configs for the platform. On Linux that is only Windsurf
``.codeium/windsurf/mcp_config.json``, Cursor ``.cursor/mcp.json`` and VS Code
``.vscode/mcp.json`` + ``.config/Code/User/settings.json``; Claude Desktop is
looked up only on macOS and Windows, and Claude Code, Gemini CLI, Codex and
``.config/Code/User/mcp.json`` are never read. ``yara`` is the only analyzer
that works without an API key or network (``api`` and ``llm`` need Cisco AI
Defense or an LLM key). The tool then starts every stdio server it found to
list its tools; with no network every ``npx``/``uvx`` server fails, so
``scan_results`` is empty. Each attempt costs about 12 seconds whatever the
timeout: the environment variable bounds the process start, but the MCP
``initialize`` handshake has a hard-coded 10 second timeout. The
``--stdio-timeout`` flag still crashes this build (``UnboundLocalError`` on
``os`` in ``cli.py``), hence the environment variable. The LiteLLM import logs
one failed fetch of its model cost map and falls back to its bundled copy.

Exit code is 0 for a completed run, including one where every server failed.
Stdout (``--format raw``) is ``{"server_url": "well-known-configs",
"scan_results": [...], "requested_analyzers": ["yara"]}``; a server only
appears in ``scan_results`` when it answered. Discovery evidence is therefore
the debug log on stderr, which names every config file and server before any
connection is tried::

    ... config_parser - DEBUG - Found MCP config file: <home>/.cursor/mcp.json
    ... config_parser - WARNING - Config file not found: <home>/.vscode/mcp.json
    ... core.scanner - DEBUG - Scanning server 'filesystem' from <home>/.cursor/mcp.json

Detection rule: every ``Scanning server '<name>' from <path>`` line whose
path lies under the home becomes ``artifact:<path relative to home>`` with
label ``agent`` (several servers in one file share the key); servers that did
answer are added from ``scan_results`` when they carry a config path. A run
whose stderr holds neither a ``Found MCP config file`` nor a ``Config file not
found`` line did not enumerate the home and is an error, never an empty
result. The tool writes ``.npm/_logs`` into the home when it tries an ``npx``
server.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.shadowbench.contract import (
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

BIN = "mcp-scanner"
DISTRIBUTION = "cisco-ai-mcp-scanner"
RAW_LIMIT = 200_000

_SERVER_LINE = re.compile(r"Scanning server '(?P<name>.+?)' from (?P<path>.+?)\s*$")
_CONFIG_LINE = re.compile(r"(Found MCP config file|Config file not found): ")


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


class CiscoMCPScanner:
    name = "cisco-mcp-scanner"
    display = "Cisco MCP Scanner"
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
        argv = (binary, "--analyzers", "yara", "--format", "raw", "--log-level", "debug", "known-configs")
        environ = {**base_env(case.home, work), "MCP_SCANNER_STDIO_TIMEOUT": "2"}
        # ~12 s per enumerated stdio server (see module docstring); well-known configs are few.
        return [Invocation(argv=argv, cwd=work, env=environ, timeout=600)]

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
        results = doc.get("scan_results") if doc else None
        if run.code != 0 or not isinstance(results, list):
            return AdapterResult("error", note=f"exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw)
        if not _CONFIG_LINE.search(run.stderr):
            note = "stderr has no well-known config enumeration log; the home was not scanned"
            return AdapterResult("error", note=note, raw=raw)
        found: dict[str, Entity] = {}
        enumerated = outside = 0

        def add(name: str, path: str) -> None:
            nonlocal outside
            key = relative_artifact(path, case.home) if case.home else None
            if key is None:
                outside += 1
                return
            entity = found.get(key)
            names = list(entity.attributes.get("servers", [])) if entity else []
            if name not in names:
                names.append(name)
            found[key] = Entity("mcp-server", key, "agent", {"servers": names})

        for line in run.stderr.splitlines():
            match = _SERVER_LINE.search(line)
            if match:
                enumerated += 1
                add(match.group("name"), match.group("path"))
        answered = 0
        for record in results:
            if not isinstance(record, dict):
                continue
            name = record.get("server_name") or record.get("name")
            path = record.get("config_path") or record.get("config_file")
            if isinstance(name, str) and isinstance(path, str):
                answered += 1
                add(name, path)
        note = f"enumerated={enumerated} answered={answered} outside_home={outside}"
        return AdapterResult("ok", entities=list(found.values()), note=note, raw=raw)


ADAPTER = CiscoMCPScanner()
