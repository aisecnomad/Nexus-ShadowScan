"""AgentSight: endpoint agent-session discovery from home trees (no eBPF).

Mode A only — `report prompts/audit --json` reads agent-native session
stores under $HOME. The eBPF capture mode is environment-blocked here:
fentry/fexit program loads return EPERM on this kernel, which the run
records as the reason the runtime surface stays out of scope.
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
    run_version,
    unit_path,
)
from tools.estate_benchmark.adapters.common import client_slug
from tools.estate_benchmark.corpus import EstateCorpus

SPEC = ToolSpec(
    id="agentsight",
    name="AgentSight (local sessions)",
    vendor="eunomia-bpf",
    surfaces=frozenset({"endpoint"}),
    categories=frozenset({"ai-client"}),
    notes="report prompts/audit --json over $HOME session stores; eBPF runtime capture is "
    "blocked in this environment (fentry/fexit EPERM)",
)

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
        binary = cfg.binary("agentsight")
        work = out_dir / "work"
        work.mkdir(exist_ok=True)
        script = out_dir / "run.sh"
        script.write_text(
            "#!/bin/sh\n"
            f'cd "{work}" || exit 1\n'
            f'"{binary}" report prompts --json > "{out_dir}/prompts.json" 2> "{out_dir}/prompts.err"\n'
            f'"{binary}" report audit --json > "{out_dir}/audit.json" 2> "{out_dir}/audit.err"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return [Command(argv=("/bin/sh", str(script)), env={"HOME": str(home)})]

    @staticmethod
    def _records(path: Path) -> list[dict[str, object]]:
        if not path.exists() or not path.stat().st_size:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
        start = min((idx for idx in (text.find("["), text.find("{")) if idx >= 0), default=-1)
        if start < 0:
            return []
        try:
            data = json.loads(text[start:])
        except ValueError:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        records = self._records(out_dir / "prompts.json") + self._records(out_dir / "audit.json")
        result = Normalized(raw_count=len(records))
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
