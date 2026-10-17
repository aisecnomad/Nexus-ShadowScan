# API Reference

Auto-generated reference for the ShadowScan Python API.

These pages are built from source docstrings using
[mkdocstrings](https://mkdocstrings.github.io/).

## Core data types

```python
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskLevel, ScanResult, Surface

# Finding fields
finding.id                    # "ss-3f9c1e2a7b4d8c10"
finding.surface               # Surface.CODE | .IDENTITY | .GATEWAY | ...
finding.kind                  # Kind.AGENT | .MCP_SERVER | .OAUTH_GRANT | ...
finding.title                 # human-readable summary
finding.risk.score            # 0-100
finding.risk.level            # RiskLevel.CRITICAL | .HIGH | .MEDIUM | .LOW | .INFO
finding.shadow                # True if not in inventory
finding.confidence            # 0.0-1.0 heuristic evidence score
finding.evidence              # list[Evidence] with signal, description, weight
finding.metadata["autonomy"]  # {"floor": 2, "floor_label": "L2 Supervised", "ceiling": 5, ...}
finding.to_dict()["metadata"]["threats"]   # OWASP, MITRE ATLAS, MAESTRO references (derived on export)
finding.to_dict()["metadata"]["controls"]  # NIST AI RMF, ISO 42001, EU AI Act, AIUC-1 references
```

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
| [Signatures](signatures.md) | Signature schema, loading and the matcher index behind every connector |
| [Threat and control mappings](mappings.md) | Edition-qualified threat and control references |

## Reports and Fleet

| Module | Description |
|--------|-------------|
| [Fleet merge](fleet.md) | Combining reports from several machines or scans |
| [Dashboard](dashboard.md) | The `shadowscan.inventory/v1` document behind `shadowscan dashboard` |
| [Control evidence](controls.md) | Findings per governance control for `shadowscan controls` |
| [Reporters](reporters.md) | Output formats behind `--format`: table, JSON, SARIF, CSV, Markdown, HTML, CycloneDX, OCSF |

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
