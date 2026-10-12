"""Estate adapter registry.

Separate from `tools.discovery_benchmark.adapters.registry` on purpose:
registering a tool here never changes the code-surface benchmark's runs,
scopes or scores. Third-party adapters are appended as they are validated;
a tool that cannot run in the benchmark environment is recorded in the run's
`tools_skipped` with its blocker instead of silently disappearing.
"""

from __future__ import annotations

from tools.shadowbench.estate.adapters import Adapter
from tools.shadowbench.estate.adapters.agentsight_estate import AgentSightAdapter
from tools.shadowbench.estate.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.shadowbench.estate.adapters.cisco_mcp_scanner import CiscoMcpScannerAdapter
from tools.shadowbench.estate.adapters.code_wrappers import (
    AgentDiscoverEstateAdapter,
    AgenticRadarEstateAdapter,
    VetEstateAdapter,
)
from tools.shadowbench.estate.adapters.mcp_scan import McpScanAdapter
from tools.shadowbench.estate.adapters.not_runnable import CartographyAdapter, PowerPwnAdapter
from tools.shadowbench.estate.adapters.numbat import NumbatAdapter
from tools.shadowbench.estate.adapters.shadowscan_estate import ShadowScanEstateAdapter


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
