"""Load every adapter module in this package and expose them by name."""

from __future__ import annotations

import importlib
import pkgutil

from tools.shadowbench.synthetic import adapters as _pkg
from tools.shadowbench.synthetic.contract import Adapter

_SKIP = {"registry"}


def load_adapters() -> tuple[dict[str, Adapter], dict[str, str]]:
    """Return (adapters by name, import problems by module)."""
    found: dict[str, Adapter] = {}
    problems: dict[str, str] = {}
    for info in sorted(pkgutil.iter_modules(_pkg.__path__), key=lambda m: m.name):
        if info.name in _SKIP or info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{_pkg.__name__}.{info.name}")
        except Exception as exc:  # noqa: BLE001 - a broken third-party adapter must not stop the others
            problems[info.name] = f"{type(exc).__name__}: {exc}"
            continue
        adapter = getattr(module, "ADAPTER", None)
        if adapter is None:
            problems[info.name] = "module defines no ADAPTER"
            continue
        found[adapter.name] = adapter
    return found, problems
