"""Estate adapter registry.

Separate from `tools.discovery_benchmark.adapters.registry` on purpose:
registering a tool here never changes the code-surface benchmark's runs,
scopes or scores. Third-party adapters are appended as they are validated;
a tool that cannot run in the benchmark environment is recorded in the run's
`tools_skipped` with its blocker instead of silently disappearing.
"""

from __future__ import annotations

from tools.estate_benchmark.adapters import Adapter
from tools.estate_benchmark.adapters.shadowscan_estate import ShadowScanEstateAdapter


def all_adapters() -> list[Adapter]:
    """Every estate adapter, in report order."""
    return [
        ShadowScanEstateAdapter(),
    ]


def adapters_by_id() -> dict[str, Adapter]:
    return {adapter.spec.id: adapter for adapter in all_adapters()}
