"""Cisco MCP Scanner: endpoint MCP discovery from well-known client configs.

YARA analyzer only (no API keys, no network). The scanner enumerates tools by
actually connecting to each configured MCP server; the benchmark never
executes corpus content, and its configs reference nonexistent commands, so
servers it cannot launch are absent from scan_results. That behavior is part
of what the benchmark measures, and the run also passes the Claude config
files explicitly because the Linux known-configs list omits them.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.estate_benchmark.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    home_units,
    python_package_version,
    unit_path,
)
from tools.estate_benchmark.corpus import EstateCorpus

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
        binary = cfg.binary("cisco_mcp_scanner")
        lines = [
            "#!/bin/sh",
            f'"{binary}" --analyzers yara --format raw known-configs '
            f'> "{out_dir}/known.json" 2> "{out_dir}/known.err"',
        ]
        for index, rel in enumerate(_CLAUDE_CONFIGS):
            config = home / rel
            if config.exists():
                lines.append(
                    f'"{binary}" --analyzers yara --format raw config --config-path "{config}" '
                    f'> "{out_dir}/config{index}.json" 2> "{out_dir}/config{index}.err"'
                )
        lines.append("exit 0")
        script = out_dir / "run.sh"
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        script.chmod(0o755)
        env = {"HOME": str(home), "LITELLM_LOCAL_MODEL_COST_MAP": "True"}
        return [Command(argv=("/bin/sh", str(script)), env=env)]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        result = Normalized()
        found_any_output = False
        for path in sorted(out_dir.glob("*.json")):
            if path.name == "result.json" or not path.stat().st_size:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            found_any_output = True
            rows = data.get("scan_results") or []
            if not isinstance(rows, list):
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
        if not found_any_output:
            result.error = "no scanner output parsed"
        return result
