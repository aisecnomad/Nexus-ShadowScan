# API Reference

Auto-generated reference for the ShadowScan Python API.

These pages are built from source docstrings using
[mkdocstrings](https://mkdocstrings.github.io/).

## Core Modules

| Module | Description |
|--------|-------------|
| [Engine](engine.md) | Scan orchestration and concurrent connector execution |
| [Models](models.md) | Finding, Evidence, ScanResult and supporting data types |
| [Config](config.md) | Scan configuration parsing and validation |
| [Risk](risk.md) | Risk scoring and policy |
| [Autonomy](autonomy.md) | Autonomy tier interval (L0 to L5) and declared-level comparison |
| [Merge](merge.md) | Finding deduplication and merge logic |
| [Correlation](correlation.md) | Cross-surface, runtime and lifecycle correlation |
| [Incremental cache](incremental.md) | Content-addressed reuse of completed static connector results |
| [Comparison](comparison.md) | Collection scope provenance and report comparison (`diff`) |
| [LLM triage](triage.md) | Opt-in advisory verdicts on the highest-risk findings |

## Assessment

| Module | Description |
|--------|-------------|
| [Inventory registry](registry.md) | Sanctioned agent inventory and reconciliation |
| [Vendor registries](registries.md) | Registry record contract, reconciliation statuses and trusted-registry approvals |
| [MCP registry](mcp_registry.md) | MCP Registry snapshots, server provenance and approved MCP catalogs |
| [Declared governance](governance.md) | Governance facts declared in Capability Cards |
| [Threat and control mappings](mappings.md) | Edition-qualified threat and control references |

## Reports and Fleet

| Module | Description |
|--------|-------------|
| [Fleet merge](fleet.md) | Combining reports from several machines or scans |
| [Dashboard](dashboard.md) | The `shadowscan.inventory/v1` document behind `shadowscan dashboard` |
| [Control evidence](controls.md) | Findings per governance control for `shadowscan controls` |

## Connector Framework

| Module | Description |
|--------|-------------|
| [Base connector](base.md) | ABC for all connectors |
| [Offline input](offline.md) | Shared offline export reading |
| [Connector helpers](common.md) | Turning signature matches into findings |

## Utilities

| Module | Description |
|--------|-------------|
| [HTTP client](http.md) | SSRF-safe HTTP transport |
| [Redaction](redaction.md) | Credential sanitization |
