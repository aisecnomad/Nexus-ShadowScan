"""Adapter contract for the estate benchmark.

An adapter runs one discovery tool against the estate units it understands
and normalizes the tool's output into taxonomy facts with attribution text.
The registry in `registry.py` is separate from the code-surface benchmark's
registry on purpose: registering a tool here never changes the code-surface
benchmark's runs or scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from tools.discovery_benchmark.adapters import (
    ToolConfig,
    load_json,
    python_package_version,
    run_version,
)
from tools.shadowbench.corpus import EstateCorpus

__all__ = [
    "Adapter",
    "Command",
    "Normalized",
    "Prediction",
    "ToolConfig",
    "ToolSpec",
    "load_json",
    "python_package_version",
    "run_version",
]


@dataclass(frozen=True)
class Command:
    """One subprocess invocation; cwd is the per-run output directory."""

    argv: tuple[str, ...]
    ok_exit_codes: frozenset[int] = frozenset({0})
    env: dict[str, str] = field(default_factory=dict)
    timeout: int | None = None


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    vendor: str
    surfaces: frozenset[str]
    categories: frozenset[str]
    notes: str = ""


@dataclass(frozen=True)
class Prediction:
    """One normalized tool claim: a fact plus the text used for attribution.

    `text` should carry the tool's own identifiers for the finding (resource
    ids, paths, names); entity anchors are matched against it
    case-insensitively. `surface` is the adapter's placement of the claim.
    `shadow` carries a registry-reconciliation verdict when the tool makes
    one (True = shadow, False = registered), else None.
    """

    fact: str
    text: str
    surface: str
    shadow: bool | None = None


@dataclass
class Normalized:
    predictions: list[Prediction] = field(default_factory=list)
    raw_count: int = 0
    detail: dict[str, object] = field(default_factory=dict)
    error: str | None = None
    incomplete: bool = False


class Adapter(Protocol):
    """Protocol every estate adapter implements."""

    spec: ToolSpec

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        """A human-readable reason to skip the tool, or None to run it."""
        ...  # pragma: no cover

    def version(self, cfg: ToolConfig) -> str:
        """The tool version string, probed from the binary."""
        ...  # pragma: no cover

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        """Unit ids this tool runs on: 'estate', 'code:<repo>', 'home:<device>'."""
        ...  # pragma: no cover

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        """Commands to run for one unit; outputs go under out_dir."""
        ...  # pragma: no cover

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        """Map stored tool output for one unit onto taxonomy predictions."""
        ...  # pragma: no cover


def code_units(estate: Path) -> list[str]:
    """One unit per authored repository under estate/code/."""
    root = estate / "code"
    if not root.is_dir():
        return []
    return sorted(f"code:{path.name}" for path in root.iterdir() if path.is_dir())


def home_units(estate: Path) -> list[str]:
    """One unit per device home tree under estate/home/<device>/<user>/."""
    root = estate / "home"
    if not root.is_dir():
        return []
    return sorted(f"home:{path.name}" for path in root.iterdir() if path.is_dir())


def unit_path(unit: str, estate: Path) -> Path:
    """The filesystem path a unit id refers to.

    For home units this is the USER directory (the fake $HOME), not the
    device directory: `home:<device>` resolves to the single user tree below
    `estate/home/<device>/`.
    """
    if unit == "estate":
        return estate
    kind, _, name = unit.partition(":")
    if kind == "code":
        return estate / "code" / name
    if kind == "home":
        device = estate / "home" / name
        users = [path for path in sorted(device.iterdir()) if path.is_dir()]
        if len(users) != 1:
            raise ValueError(f"home unit {unit} must hold exactly one user tree")
        return users[0]
    raise ValueError(f"unknown unit {unit}")
