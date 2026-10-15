"""MCPProxy network and endpoint scanner for MCP (Model Context Protocol) servers.

Build (checkout of github.com/mcpproxy/mcpproxy at commit 7a2e5d9f1b3c,
go.mod ``go 1.24.0``; installs with ``go build``)::

    CGO_ENABLED=0 go build -trimpath -o <tool_root>/bin/mcpproxy ./cmd/mcpproxy

MCPProxy has two modes:

1. Network active scan (``network/active``): connects to staged services and
   fingerprints MCP protocol responses (the SSE transport, the Streamable HTTP
   transport, and the JSON-RPC handshake). Each staged service is given as a
   comma-separated ``ip:port`` list::

       mcpproxy scan --targets <ip:port,...> --output <work>/mcp.json

2. Endpoint home discovery (``endpoint/home``): reads well-known MCP
   configuration files under a user's home directory (Claude Desktop config,
   Cursor ``mcp.json``, VS Code ``mcp.json``, ``.mcp.json``, Gemini CLI,
   Codex, Windsurf and Claude Code settings) and reports each configured
   server::

       mcpproxy discover --home <home> --output <work>/mcp.json

``HOME`` is set to the case home for endpoint scans and to the work directory
for network scans. Exit code 0 is a completed scan; any other exit code is an
error.

Output: a JSON object. For network scans it has a ``services`` array, each
element carrying ``host``, ``port`` (integer), ``protocol`` (``mcp-sse``,
``mcp-streamable-http``, ``jsonrpc``, ``http``, ``unknown``), ``server_name``
(from the MCP ``initialize`` response, empty when the service did not answer
the MCP handshake), ``tools`` (list of tool names from ``tools/list``, empty
when the handshake failed) and ``label`` (``agent`` for services that
completed the MCP handshake and listed tools, ``llm`` for services that
answered HTTP with AI-related headers or paths but did not speak MCP,
``none`` for services that did not answer or showed no AI signal). For
endpoint scans it has a ``configs`` array, each element carrying ``path``
(absolute path to the configuration file), ``client`` (the MCP client name),
``servers`` (list of server name strings), and ``label`` (always ``agent``
for a file with configured servers).

Detection rules:

* network/active: every service with a non-``none`` label maps to
  ``service:<host>:<port>`` with the tool's label. A run that produces no
  result for a staged target is an error (the target was not scanned).
* endpoint/home: every config entry whose ``path`` lies under the case home
  maps to ``artifact:<path relative to home>`` with label ``agent``. A path
  outside the home is dropped.

Fail closed: a missing, empty or unparseable report after exit 0, or an
entry in the services or configs array that is not an object, is an error,
never an empty inventory. For network scans, a staged target missing from the
results is also an error.

``version()`` runs ``mcpproxy --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout) unless ``tools.json`` pins a version.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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

BIN = "mcpproxy"
REPORT = "mcp.json"
RAW_LIMIT = 200_000


class MCPProxyAdapter:
    name = "mcpproxy"
    display = "MCPProxy (MCP protocol scanner)"
    surfaces: Mapping[str, frozenset[str]] = {
        "network": frozenset({"active"}),
        "endpoint": frozenset({"home"}),
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

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        binary = env.binary(BIN) or BIN
        output = str(work / REPORT)
        if case.surface == "network":
            targets = _staged_targets(case)
            if not targets:
                return []
            argv: tuple[str, ...] = (binary, "scan", "--targets", ",".join(targets), "--output", output)
        else:
            home = case.home
            if home is None:
                return []
            argv = (binary, "discover", "--home", str(home), "--output", output)
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="mcpproxy did not run")
        run = runs[0]
        raw: dict[str, Any] = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult(status="error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        report_path = work / REPORT
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"mcpproxy exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw
            )
        if not report_path.exists():
            return AdapterResult(
                status="error", note=f"mcpproxy exited 0 but wrote no {REPORT}", raw=raw
            )
        try:
            doc = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(status="error", note=f"{REPORT} is unreadable: {exc}", raw=raw)
        if not isinstance(doc, dict):
            return AdapterResult(status="error", note=f"{REPORT} is not a JSON object", raw=raw)
        if case.surface == "network":
            return self._normalize_network(doc, case, raw)
        return self._normalize_endpoint(doc, case, raw)

    @staticmethod
    def _normalize_network(
        doc: dict[str, Any], case: MaterializedCase, raw: dict[str, Any]
    ) -> AdapterResult:
        services = doc.get("services")
        if not isinstance(services, list):
            return AdapterResult(status="error", note=f"{REPORT} has no 'services' array", raw=raw)
        if not all(isinstance(s, dict) for s in services):
            return AdapterResult(
                status="error", note=f"{REPORT} has a service entry that is not an object", raw=raw
            )
        staged = set(_staged_targets(case))
        reported: set[str] = set()
        entities: dict[str, Entity] = {}
        for service in services:
            host = str(service.get("host") or "")
            port = service.get("port")
            if not host or port is None:
                continue
            target = f"{host}:{port}"
            reported.add(target)
            label = str(service.get("label") or "none")
            if label == "none":
                continue
            key = f"service:{host}:{port}"
            if key in entities:
                current = entities[key]
                if current.label == "agent" or (current.label == label):
                    continue
            entities[key] = Entity(
                kind="service",
                key=key,
                label=label,
                attributes={
                    "protocol": str(service.get("protocol") or ""),
                    "server_name": str(service.get("server_name") or ""),
                    "tools": service.get("tools") or [],
                    "staged": target in staged,
                },
            )
        missing = sorted(staged - reported)
        if missing:
            note = f"no result for staged target(s) {', '.join(missing)}: the scan is partial"
            raw["missing"] = missing
            return AdapterResult(status="error", note=note, raw=raw)
        note = f"services={len(services)} entities={len(entities)}"
        return AdapterResult(status="ok", entities=list(entities.values()), note=note, raw=raw)

    @staticmethod
    def _normalize_endpoint(
        doc: dict[str, Any], case: MaterializedCase, raw: dict[str, Any]
    ) -> AdapterResult:
        if case.home is None:
            return AdapterResult(status="error", note="case has no home directory", raw=raw)
        configs = doc.get("configs")
        if not isinstance(configs, list):
            return AdapterResult(status="error", note=f"{REPORT} has no 'configs' array", raw=raw)
        if not all(isinstance(c, dict) for c in configs):
            return AdapterResult(
                status="error", note=f"{REPORT} has a config entry that is not an object", raw=raw
            )
        entities: dict[str, Entity] = {}
        outside = 0
        for config in configs:
            path = config.get("path")
            if not isinstance(path, str) or not path:
                continue
            key = relative_artifact(path, case.home)
            if key is None:
                outside += 1
                continue
            if key in entities:
                # Merge server names into the existing entity.
                current = entities[key]
                names = list(current.attributes.get("servers", []))
                for name in config.get("servers") or []:
                    if isinstance(name, str) and name not in names:
                        names.append(name)
                entities[key] = Entity(
                    kind="mcp-config",
                    key=key,
                    label="agent",
                    attributes={"client": current.attributes.get("client", ""), "servers": names},
                )
                continue
            entities[key] = Entity(
                kind="mcp-config",
                key=key,
                label="agent",
                attributes={
                    "client": str(config.get("client") or ""),
                    "servers": [s for s in (config.get("servers") or []) if isinstance(s, str)],
                },
            )
        note = f"configs={len(configs)} entities={len(entities)} outside_home={outside}"
        return AdapterResult(status="ok", entities=list(entities.values()), note=note, raw=raw)


def _staged_targets(case: MaterializedCase) -> list[str]:
    """The ``ip:port`` of every staged service, for the ``--targets`` flag."""
    targets: list[str] = []
    for service in case.services:
        port = service.get("port")
        if port is not None:
            targets.append(f"{service.get('ip') or '127.0.0.1'}:{port}")
    return targets


ADAPTER = MCPProxyAdapter()
