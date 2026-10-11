"""Estate adapter registry.

Separate from `tools.discovery_benchmark.adapters.registry` on purpose:
registering a tool here never changes the code-surface benchmark's runs,
scopes or scores. Third-party adapters are appended as they are validated;
a tool that cannot run in the benchmark environment is recorded in the run's
`tools_skipped` with its blocker instead of silently disappearing.
"""

from __future__ import annotations

from tools.estate_benchmark.adapters import Adapter
from tools.estate_benchmark.adapters.agentsight_estate import AgentSightAdapter
from tools.estate_benchmark.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.estate_benchmark.adapters.cisco_mcp_scanner import CiscoMcpScannerAdapter
from tools.estate_benchmark.adapters.code_wrappers import (
    AgentDiscoverEstateAdapter,
    AgenticRadarEstateAdapter,
    VetEstateAdapter,
)
from tools.estate_benchmark.adapters.mcp_scan import McpScanAdapter
from tools.estate_benchmark.adapters.not_runnable import CartographyAdapter, PowerPwnAdapter
from tools.estate_benchmark.adapters.numbat import NumbatAdapter
from tools.estate_benchmark.adapters.shadowscan_estate import ShadowScanEstateAdapter


def all_adapters() -> list[Adapter]:
    """Every estate adapter, in report order."""
    return [
        ShadowScanEstateAdapter(),
        McpScanAdapter(),
        NumbatAdapter(),
        AgenticRadarEstateAdapter(),
        AgentSightAdapter(),
        AiInfraGuardAdapter(),
        CiscoMcpScannerAdapter(),
        VetEstateAdapter(),
        AgentDiscoverEstateAdapter(),
        PowerPwnAdapter(),
        CartographyAdapter(),
    ]


def adapters_by_id() -> dict[str, Adapter]:
    return {adapter.spec.id: adapter for adapter in all_adapters()}
