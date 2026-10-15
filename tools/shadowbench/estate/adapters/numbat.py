"""Numbat (Perplexity): endpoint agent inventory from home trees.

`numbat agents` inventories installed agents from their root directories and
at-rest transcripts; `numbat scan` emits evidence records whose local paths
help anchor attribution. Both run fully local.

The adapter reads `agents.json` as a list of agent records: objects with an
`agent` name and a `present` or `detected` field. An empty list is an empty
inventory. A list that holds entries but no agent record (`[{"error": ...}]`,
or rows without the agent fields) is an adapter error, never an empty
inventory. Other rows beside a record are skipped.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    home_units,
    run_version,
    unit_path,
)
from tools.shadowbench.estate.adapters.common import client_slug, sh_command, write_script
from tools.shadowbench.estate.corpus import EstateCorpus

SPEC = ToolSpec(
    id="numbat",
    name="Numbat",
    vendor="Perplexity",
    surfaces=frozenset({"endpoint"}),
    categories=frozenset({"ai-client"}),
    notes="agents --format json plus scan --emit all; local only",
)


def _agent_record(entry: object) -> bool:
    """Whether an `agents.json` row is an agent record: an `agent` name and `present` or `detected`."""
    if not isinstance(entry, dict):
        return False
    name = entry.get("agent")
    return isinstance(name, str) and bool(name) and ("present" in entry or "detected" in entry)


class NumbatAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("numbat") else "no 'bin' configured for numbat"

    def version(self, cfg: ToolConfig) -> str:
        return run_version([cfg.binary("numbat") or "numbat", "version"], pattern=r"(\d+\.\d+\.\d+\S*)")

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        home = unit_path(unit, estate)
        binary = cfg.binary("numbat") or "numbat"
        out = out_dir.absolute()
        agents = out / "agents.json"
        lines = [
            # `agents` exits 1 when no agent artifacts exist under HOME; an empty
            # inventory is a valid result. Any other non-zero status is a failure
            # even when it printed something, and a missing/empty file fails too.
            sh_command((binary, "agents", "--format", "json"), stdout=agents) + "; status=$?",
            'case "$status" in 0|1) ;; *) exit "$status" ;; esac',
            f'[ -s {shlex.quote(str(agents))} ] || exit "$status"',
            sh_command(
                (binary, "scan", "--emit", "all"), stdout=out / "scan.ndjson", stderr=out / "scan.err"
            ),
            "exit 0",
        ]
        script = write_script(out / "run.sh", lines)
        return [Command(argv=("/bin/sh", str(script)), env={"HOME": str(home)})]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        path = out_dir / "agents.json"
        if not path.exists() or not path.stat().st_size:
            return Normalized(error="agents.json missing or empty")
        try:
            agents = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return Normalized(error=f"agents.json unparseable: {exc}")
        if not isinstance(agents, list):
            return Normalized(error="agents.json is not a list")
        if agents and not any(_agent_record(entry) for entry in agents):
            return Normalized(error="agents.json holds no agent record")
        evidence: dict[str, list[str]] = {}
        scan_path = out_dir / "scan.ndjson"
        if scan_path.exists():
            for line in scan_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                source = str(record.get("source_agent", ""))
                local = str((record.get("evidence") or {}).get("local_path", ""))
                if source and local:
                    evidence.setdefault(source, [])
                    if local not in evidence[source] and len(evidence[source]) < 4:
                        evidence[source].append(local)
        result = Normalized(raw_count=len(agents))
        for entry in agents:
            if not _agent_record(entry):
                continue
            if not (entry.get("present") or entry.get("detected")):
                continue
            name = str(entry.get("agent", ""))
            slug = client_slug(name)
            paths = evidence.get(slug, []) + evidence.get(name.lower().replace(" ", "-"), [])
            text = " ".join([name, *paths])
            result.predictions.append(Prediction(fact=f"ai-client:{slug}", text=text, surface="endpoint"))
        return result
