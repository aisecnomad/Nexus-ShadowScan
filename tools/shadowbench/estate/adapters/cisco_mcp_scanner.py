"""Cisco MCP Scanner: endpoint MCP discovery from well-known client configs.

YARA analyzer only (no API keys, no network). The scanner enumerates tools by
actually connecting to each configured MCP server, and servers it cannot
launch are absent from scan_results; that behavior is part of what the
benchmark measures. The run also passes the Claude config files explicitly
because the Linux known-configs list omits them.

The wrapper puts refusing shims for the common server launchers (`npx`,
`uvx`, `docker`, `python3`, ... see `common.LAUNCHERS`) first on PATH, so a
server configured with one of those names fails to start whatever the host
has installed. The scanner runs from its configured virtualenv binary and
needs none of them. Only those names are refused: any other command the host
has on PATH (`sh`, `bash`, `perl`, ...), an absolute command path, or a
configuration that sets its own PATH still runs, so the tool belongs on a
disposable runner. The committed corpus's home configurations name only
`npx` and one absolute path under `/home/dana/tools/`, which the corpus does
not ship: it runs only if the runner itself has that file.

Every scanner step runs; the script exits with the first non-zero status, so
a crash never reads as an empty inventory. Each `--format raw` output must be
an object whose `scan_results` is a list (`{"server_url": ...,
"scan_results": [...], ...}`); a missing, empty or unparseable output, or one
without that list, is an adapter error.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    STATUS_EXIT,
    STATUS_INIT,
    refuse_launchers,
    sh_step,
    write_script,
)
from tools.shadowbench.estate.corpus import EstateCorpus

SPEC = ToolSpec(
    id="cisco_mcp_scanner",
    name="Cisco MCP Scanner",
    vendor="Cisco AI Defense",
    surfaces=frozenset({"endpoint"}),
    categories=frozenset({"mcp"}),
    notes="yara analyzer only; tool enumeration requires launching each server, which the "
    "benchmark forbids, so dead-command configs yield no inventory",
)

_CLAUDE_CONFIGS = (
    ".claude.json",
    ".config/Claude/claude_desktop_config.json",
    "AppData/Roaming/Claude/claude_desktop_config.json",
)


class CiscoMcpScannerAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("cisco_mcp_scanner") else "no 'bin' configured for cisco_mcp_scanner"

    def version(self, cfg: ToolConfig) -> str:
        binary = cfg.binary("cisco_mcp_scanner") or "mcp-scanner"
        python = str(Path(binary).parent / "python")
        return python_package_version(python, "cisco-ai-mcp-scanner")

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        home = unit_path(unit, estate)
        binary = cfg.binary("cisco_mcp_scanner") or "mcp-scanner"
        out = out_dir.absolute()
        base = (binary, "--analyzers", "yara", "--format", "raw")
        lines = [
            *refuse_launchers(out / "shims"),
            STATUS_INIT,
            sh_step((*base, "known-configs"), stdout=out / "known.json", stderr=out / "known.err"),
        ]
        for index, rel in enumerate(_CLAUDE_CONFIGS):
            config = home / rel
            if config.exists():
                lines.append(
                    sh_step(
                        (*base, "config", "--config-path", str(config)),
                        stdout=out / f"config{index}.json",
                        stderr=out / f"config{index}.err",
                    )
                )
        lines.append(STATUS_EXIT)
        script = write_script(out / "run.sh", lines)
        env = {"HOME": str(home), "LITELLM_LOCAL_MODEL_COST_MAP": "True"}
        return [Command(argv=("/bin/sh", str(script)), env=env)]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        result = Normalized()
        outputs = sorted(path for path in out_dir.glob("*.json") if path.name != "result.json")
        problems: list[str] = []
        if not any(path.name == "known.json" for path in outputs):
            problems.append("known.json missing")
        for path in outputs:
            if not path.stat().st_size:
                problems.append(f"{path.name} empty")
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                problems.append(f"{path.name} unparseable")
                continue
            if not isinstance(data, dict):
                problems.append(f"{path.name} is not an object")
                continue
            rows = data.get("scan_results")
            if not isinstance(rows, list):
                # A missing or null list is an error report, not zero servers.
                problems.append(f"{path.name} scan_results is missing or not a list")
                continue
            result.raw_count += len(rows)
            seen: set[str] = set()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                source = str(row.get("server_source", ""))
                if source in seen:
                    continue
                seen.add(source)
                result.predictions.append(
                    Prediction(
                        fact="mcp:server",
                        text=f"{source} {row.get('tool_name', '')}",
                        surface="endpoint",
                    )
                )
        if problems:
            result.error = "scanner output unusable: " + "; ".join(problems)
        return result
