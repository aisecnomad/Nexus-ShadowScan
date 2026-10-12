"""AgentSight: endpoint agent-session discovery from home trees (no eBPF).

Mode A only — `report prompts/audit --json` reads agent-native session
stores under $HOME. The eBPF capture mode is environment-blocked here:
fentry/fexit program loads return EPERM on this kernel, which the run
records as the reason the runtime surface stays out of scope. Both reports
run; the script exits with the first non-zero status, and a missing, empty or
unparseable report, or one that holds JSON but no session record, is an
adapter error, never an empty session list.
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
from tools.shadowbench.estate.adapters.common import (
    STATUS_EXIT,
    STATUS_INIT,
    client_slug,
    sh_step,
    write_script,
)
from tools.shadowbench.estate.corpus import EstateCorpus

SPEC = ToolSpec(
    id="agentsight",
    name="AgentSight (local sessions)",
    vendor="eunomia-bpf",
    surfaces=frozenset({"endpoint"}),
    categories=frozenset({"ai-client"}),
    notes="report prompts/audit --json over $HOME session stores; eBPF runtime capture is "
    "blocked in this environment (fentry/fexit EPERM)",
)

_REPORTS = ("prompts", "audit")

_COMM_SLUGS = {
    "claude": "claude-code",
    "codex": "codex",
    "gemini": "gemini-cli",
    "codebuddy": "generic",
}


class AgentSightAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("agentsight") else "no 'bin' configured for agentsight"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("agentsight") or "agentsight", "--version"], pattern=r"(\d+\.\d+\.\d+\S*)"
        )

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        home = unit_path(unit, estate)
        binary = cfg.binary("agentsight") or "agentsight"
        out = out_dir.absolute()
        work = out / "work"
        work.mkdir(exist_ok=True)
        lines = [STATUS_INIT, f"cd {shlex.quote(str(work))} || exit 1"]
        for report in _REPORTS:
            lines.append(
                sh_step(
                    (binary, "report", report, "--json"),
                    stdout=out / f"{report}.json",
                    stderr=out / f"{report}.err",
                )
            )
        lines.append(STATUS_EXIT)
        script = write_script(out / "run.sh", lines)
        return [Command(argv=("/bin/sh", str(script)), env={"HOME": str(home)})]

    @staticmethod
    def _records(path: Path) -> tuple[list[dict[str, object]], str | None]:
        """The report's session records, or an error when the report is not a session report.

        An empty list is an empty report. A missing, empty or non-JSON file is
        an error, and so is an object or non-empty list without one record
        that names its agent (`comm`): `{"error": ...}` is not zero sessions.
        """
        if not path.exists() or not path.stat().st_size:
            return [], f"{path.name} missing or empty"
        text = path.read_text(encoding="utf-8", errors="replace")
        start = min((idx for idx in (text.find("["), text.find("{")) if idx >= 0), default=-1)
        if start < 0:
            return [], f"{path.name} holds no JSON"
        try:
            data = json.loads(text[start:])
        except ValueError as exc:
            return [], f"{path.name} unparseable: {exc}"
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return [], f"{path.name} is not an object or a list"
        records = [item for item in data if isinstance(item, dict)]
        if data and not any(record.get("comm") for record in records):
            return [], f"{path.name} holds no session record with a 'comm' field"
        return records, None

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        records: list[dict[str, object]] = []
        errors: list[str] = []
        for report in _REPORTS:
            found, error = self._records(out_dir / f"{report}.json")
            records.extend(found)
            if error:
                errors.append(error)
        result = Normalized(raw_count=len(records), error="; ".join(errors) or None)
        seen: set[str] = set()
        for record in records:
            comm = str(record.get("comm", "")).lower()
            slug = _COMM_SLUGS.get(comm) or client_slug(comm)
            if not comm:
                continue
            key = f"{comm}:{record.get('conversation_id', '')}"
            if key in seen:
                continue
            seen.add(key)
            text = " ".join(
                str(record.get(field, "")) for field in ("comm", "model", "conversation_id", "call_kind")
            )
            result.predictions.append(Prediction(fact=f"ai-client:{slug}", text=text, surface="endpoint"))
        return result
