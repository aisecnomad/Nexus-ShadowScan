"""Estate wrappers around the code-surface benchmark's adapters.

Each wrapper runs one authored repository per unit through the exact
commands and normalization of the corresponding `tools.discovery_benchmark`
adapter, then lifts the resulting code-taxonomy facts into estate
predictions. Behavior on the code surface is therefore identical to the
code-surface benchmark's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from tools.discovery_benchmark.adapters import Command as CodeCommand
from tools.discovery_benchmark.adapters import Normalized as CodeNormalized
from tools.discovery_benchmark.adapters.agentdiscover import AgentDiscoverAdapter
from tools.discovery_benchmark.adapters.agentic_radar import AgenticRadarAdapter
from tools.discovery_benchmark.adapters.vet import VetAdapter
from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    code_units,
    home_units,
    unit_path,
)
from tools.shadowbench.estate.adapters.common import client_slug
from tools.shadowbench.estate.corpus import EstateCorpus


class _CodeAdapter(Protocol):
    def unavailable_reason(self, cfg: ToolConfig) -> str | None: ...  # pragma: no cover

    def version(self, cfg: ToolConfig) -> str: ...  # pragma: no cover

    def commands(
        self, cfg: ToolConfig, repo_dir: Path, out_dir: Path
    ) -> list[CodeCommand]: ...  # pragma: no cover

    def normalize(self, out_dir: Path) -> Normalized | CodeNormalized: ...  # pragma: no cover


def _convert_commands(commands: list[CodeCommand]) -> list[Command]:
    return [Command(argv=c.argv, ok_exit_codes=c.ok_exit_codes, env=dict(c.env)) for c in commands]


def _lift(normalized: CodeNormalized, unit: str) -> Normalized:
    repo = unit.partition(":")[2]
    result = Normalized(raw_count=normalized.raw_count, error=normalized.error)
    result.detail = dict(normalized.detail)
    result.incomplete = bool(normalized.detail.get("incomplete"))
    per_fact_text: dict[str, list[str]] = {}
    for item in normalized.detail.get("mapped", []) or []:
        if not isinstance(item, dict):
            continue
        location = " ".join(str(item.get(key, "")) for key in ("resource", "kind") if item.get(key))
        for fact in item.get("facts") or []:
            per_fact_text.setdefault(str(fact), []).append(location)
    for fact in sorted(normalized.facts):
        extras = " ".join(per_fact_text.get(fact, [])[:3])
        result.predictions.append(Prediction(fact=fact, text=f"{repo} {extras}".strip(), surface="code"))
    return result


class _WrappedCodeAdapter:
    """Run an existing code-surface adapter over each authored repository."""

    inner: _CodeAdapter
    spec: ToolSpec

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return self.inner.unavailable_reason(cfg)

    def version(self, cfg: ToolConfig) -> str:
        return self.inner.version(cfg)

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return code_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        return _convert_commands(self.inner.commands(cfg, unit_path(unit, estate), out_dir))

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        normalized = self.inner.normalize(out_dir)
        if isinstance(normalized, Normalized):  # pragma: no cover - inner adapters return code shape
            return normalized
        return _lift(normalized, unit)


class AgenticRadarEstateAdapter(_WrappedCodeAdapter):
    def __init__(self) -> None:
        self.inner = AgenticRadarAdapter()
        inner_spec = self.inner.spec
        self.spec = ToolSpec(
            id=inner_spec.id,
            name=inner_spec.name,
            vendor=inner_spec.vendor,
            surfaces=frozenset({"code"}),
            categories=inner_spec.categories,
            notes=inner_spec.notes,
        )


class AgentDiscoverEstateAdapter(_WrappedCodeAdapter):
    def __init__(self) -> None:
        self.inner = AgentDiscoverAdapter()
        inner_spec = self.inner.spec
        self.spec = ToolSpec(
            id=inner_spec.id,
            name=inner_spec.name,
            vendor=inner_spec.vendor,
            surfaces=frozenset({"code"}),
            categories=inner_spec.categories,
            notes=inner_spec.notes,
        )


class VetEstateAdapter(_WrappedCodeAdapter):
    """vet on code repositories plus `vet ai discover` on home trees."""

    def __init__(self) -> None:
        self.inner = VetAdapter()
        inner_spec = self.inner.spec
        self.spec = ToolSpec(
            id=inner_spec.id,
            name=inner_spec.name,
            vendor=inner_spec.vendor,
            surfaces=frozenset({"code", "endpoint"}),
            categories=inner_spec.categories | frozenset({"ai-client", "mcp"}),
            notes=inner_spec.notes + "; plus endpoint ai discover over home trees",
        )

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return code_units(estate) + home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        if unit.startswith("code:"):
            return super().commands(cfg, unit, estate, out_dir)
        home = unit_path(unit, estate)
        argv = (
            cfg.binary("vet") or "vet",
            "ai",
            "discover",
            "-D",
            str(home),
            "--report-json",
            str(out_dir / "ai.json"),
            "--no-banner",
        )
        env = {
            "HOME": str(home),
            "VET_DISABLE_TELEMETRY": "true",
            "VET_TELEMETRY": "false",
        }
        return [Command(argv=argv, env=env)]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        if unit.startswith("code:"):
            return super().normalize(unit, out_dir)
        path = out_dir / "ai.json"
        if not path.exists() or not path.stat().st_size:
            return Normalized(error="ai.json missing or empty")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return Normalized(error=f"ai.json unparseable: {exc}")
        items = data if isinstance(data, list) else []
        result = Normalized(raw_count=len(items))
        for item in items:
            if not isinstance(item, dict):
                continue
            server: dict[str, Any] = item.get("MCPServer") or {}
            name = str(item.get("Name") or item.get("App") or "")
            config_path = str(item.get("ConfigPath", ""))
            if isinstance(server, dict) and (server.get("Command") or server.get("URL")):
                text = " ".join(
                    str(part)
                    for part in (
                        name,
                        config_path,
                        server.get("Command", ""),
                        " ".join(str(a) for a in server.get("Args") or []),
                        server.get("URL", ""),
                    )
                    if part
                )
                result.predictions.append(Prediction(fact="mcp:server", text=text, surface="endpoint"))
            if name or item.get("App"):
                slug = client_slug(str(item.get("App") or name))
                result.predictions.append(
                    Prediction(
                        fact=f"ai-client:{slug}",
                        text=f"{item.get('App', '')} {name} {config_path}",
                        surface="endpoint",
                    )
                )
        return result
