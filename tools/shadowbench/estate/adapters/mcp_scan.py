"""Snyk Agent Scan (formerly Invariant Labs mcp-scan): endpoint home trees.

`inspect` mode only — the default `scan` sends tool descriptions to a
verification API. stdin is /dev/null so the per-server consent prompt
auto-denies: no configured MCP server command is executed and no remote MCP
URL is contacted, yet every server is still inventoried. Refusing launcher
shims (`npx`, `uvx`, `docker`, ...) come first on PATH as well, so a consent
change in a later release still cannot start a server configured with one of
those launchers; other command names and absolute paths are not intercepted
(see `common.refuse_launchers`).

The adapter reads `inspect.json` as an object keyed by client directory or
config path whose values are client records: objects with a `servers` list,
or with a `client` name and no `servers`. An empty object is an empty
inventory. A report that holds entries but no client record (an error
object such as `{"error": ...}`, or a shape this adapter does not know) is
an adapter error, never an empty inventory. Other entries beside a record
are skipped, and a `client` that is not a string names no client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    home_units,
    python_package_version,
    unit_path,
)
from tools.shadowbench.estate.adapters.common import (
    client_slug,
    refuse_launchers,
    sh_command,
    write_script,
)
from tools.shadowbench.estate.corpus import EstateCorpus

SPEC = ToolSpec(
    id="mcp_scan",
    name="Snyk Agent Scan (mcp-scan)",
    vendor="Snyk (Invariant Labs)",
    surfaces=frozenset({"endpoint"}),
    categories=frozenset({"ai-client", "mcp"}),
    notes="inspect --json with consent auto-denied; no MCP server is executed or contacted",
)


def _client_name(entry: dict[str, Any]) -> str:
    """The entry's `client` name; a null or non-string client is no name."""
    client = entry.get("client")
    return client if isinstance(client, str) else ""


def _client_record(entry: object) -> bool:
    """Whether an `inspect.json` value is a client record: a `servers` list, or a client and no servers."""
    if not isinstance(entry, dict):
        return False
    servers = entry.get("servers")
    if isinstance(servers, list):
        return True
    # A null or empty `servers` value reads as no servers, as `servers or []` below reads it.
    return not servers and bool(_client_name(entry))


class McpScanAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("mcp_scan") else "no 'bin' configured for mcp_scan"

    def version(self, cfg: ToolConfig) -> str:
        binary = cfg.binary("mcp_scan") or "snyk-agent-scan"
        python = str(Path(binary).parent / "python")
        return python_package_version(python, "snyk-agent-scan")

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        home = unit_path(unit, estate)
        out = out_dir.absolute()
        argv = (cfg.binary("mcp_scan") or "snyk-agent-scan", "inspect", "--json")
        lines = [
            *refuse_launchers(out / "shims"),
            "exec " + sh_command(argv, stdin="/dev/null", stdout=out / "inspect.json"),
        ]
        script = write_script(out / "run.sh", lines)
        return [Command(argv=("/bin/sh", str(script)), env={"HOME": str(home)})]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        path = out_dir / "inspect.json"
        if not path.exists() or not path.stat().st_size:
            return Normalized(error="inspect.json missing or empty")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return Normalized(error=f"inspect.json unparseable: {exc}")
        if not isinstance(data, dict):
            return Normalized(error="inspect.json is not an object")
        if data and not any(_client_record(entry) for entry in data.values()):
            return Normalized(error="inspect.json holds no client record")
        result = Normalized(raw_count=0)
        for key, entry in data.items():
            if not _client_record(entry):
                continue
            client = _client_name(entry)
            servers = entry.get("servers") or []
            result.raw_count += len(servers)
            if client:
                result.predictions.append(
                    Prediction(
                        fact=f"ai-client:{client_slug(client)}",
                        text=f"{client} {key} {entry.get('path', '')}",
                        surface="endpoint",
                    )
                )
            for server in servers:
                if not isinstance(server, dict):
                    continue
                spec: dict[str, Any] = server.get("server") or {}
                text = " ".join(
                    str(part)
                    for part in (
                        server.get("name", ""),
                        server.get("config_path", ""),
                        spec.get("command", ""),
                        " ".join(str(a) for a in spec.get("args") or []),
                        spec.get("url", ""),
                        client,
                    )
                    if part
                )
                result.predictions.append(Prediction(fact="mcp:server", text=text, surface="endpoint"))
        return result
