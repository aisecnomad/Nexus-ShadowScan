"""Estate wrappers around the code-surface benchmark's adapters.

Each wrapper runs one authored repository per unit through the exact
commands and normalization of the corresponding `tools.discovery_benchmark`
adapter, then lifts the resulting code-taxonomy facts into estate
predictions. Behavior on the code surface is therefore identical to the
code-surface benchmark's: the same argv, exit codes and environment, and a
command the inner adapter runs in the repository (`cwd="repo"`, as vet's
does) still starts there. The estate runner starts every command in the run
directory, so such a command is prefixed with a fixed `/bin/sh` trampoline
that changes into the repository and execs the unchanged argv; the paths
are passed as arguments, never interpolated into shell text.
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


#: Change into the directory in $1, then exec the remaining arguments unchanged.
_IN_DIR = 'cd -- "$1" && shift && exec "$@"'


def _convert_commands(commands: list[CodeCommand], repo_dir: Path) -> list[Command]:
    converted: list[Command] = []
    for command in commands:
        argv = command.argv
        # Mirrors tools.discovery_benchmark.runner: "repo" runs in the checkout,
        # anything else in the run directory (the estate runner's default).
        if command.cwd == "repo":
            argv = ("/bin/sh", "-c", _IN_DIR, "sh", str(repo_dir.absolute()), *argv)
        converted.append(Command(argv=argv, ok_exit_codes=command.ok_exit_codes, env=dict(command.env)))
    return converted


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
        repo_dir = unit_path(unit, estate)
        return _convert_commands(self.inner.commands(cfg, repo_dir, out_dir), repo_dir)

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


def _vet_record(item: object) -> bool:
    """Whether an `ai.json` item is a vet record: an `App` or `Name`, or an `MCPServer` object."""
    if not isinstance(item, dict):
        return False
    named = any(isinstance(item.get(key), str) and item[key] for key in ("App", "Name"))
    return named or (isinstance(item.get("MCPServer"), dict) and bool(item["MCPServer"]))


def _code_report_error(path: Path) -> str | None:
    """Why a code repository's `vet.json` is not an inventory, or None.

    The code-surface adapter reads a non-list report as one item and skips
    items it cannot map, so an error object would read as nothing found.
    No report, an empty one, `null` and `[]` are left to it.
    """
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if text in {"", "null", "[]"}:
        return None
    try:
        data = json.loads(text)
    except ValueError as exc:
        return f"vet.json unparseable: {exc}"
    if not isinstance(data, list):
        return "vet.json is not a list"
    # A decoded empty list is an empty inventory however it is formatted
    # ("[ ]", "[\n]"); only a list holding items needs a vet record.
    if data and not any(_vet_record(item) for item in data):
        return "vet.json holds no vet record"
    return None


class VetEstateAdapter(_WrappedCodeAdapter):
    """vet on code repositories plus `vet ai discover` on home trees.

    On a home tree `ai.json` must be a list. `null` and an empty list read as
    nothing found: the code-surface adapter records that vet writes either
    when it finds nothing. Any other top level, or a list holding items but no
    vet record, is an adapter error, never an empty inventory. Other items
    beside a record are skipped. A code repository's `vet.json` is held to
    the same shape before the code-surface adapter reads it; a missing one
    still reads as nothing found, as that adapter records.
    """

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
            error = _code_report_error(out_dir / "vet.json")
            if error is not None:
                return Normalized(error=error)
            return super().normalize(unit, out_dir)
        path = out_dir / "ai.json"
        if not path.exists() or not path.stat().st_size:
            return Normalized(error="ai.json missing or empty")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return Normalized(error=f"ai.json unparseable: {exc}")
        if data is None:
            return Normalized()
        if not isinstance(data, list):
            return Normalized(error="ai.json is not a list")
        if data and not any(_vet_record(item) for item in data):
            return Normalized(error="ai.json holds no vet record")
        items: list[Any] = data
        result = Normalized(raw_count=len(items))
        for item in items:
            if not _vet_record(item):
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
