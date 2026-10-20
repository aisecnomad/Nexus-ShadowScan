# Compatibility contract and the 1.0 gate

ShadowScan remains alpha. This page defines the candidate compatibility boundary
to review before 1.0; adding it does not declare the current release stable.

## Public Python entry point

```python
from shadowscan.api import ConnectorSpec, ScanConfig, scan

result = scan(ScanConfig(connectors=[
    ConnectorSpec("code.filesystem", {"paths": ["./service"]})
]))
if not result.complete:
    raise SystemExit(3)
document = result.to_dict()
```

`shadowscan.api.__all__` lists the proposed supported imports. `scan(config)`
returns `ScanResult`, including findings already collected if a connector is
incomplete. It uses the same engine, parsing and connector controls as the CLI.
It does not install the CLI's process watchdog or hard-exit abandoned workers.
Run it in an externally supervised disposable process when a hard deadline is
required. The facade rejects `job_deadline_seconds` instead of silently accepting
that CLI-only option. Setup errors propagate; they are never translated into an
empty complete result.
Internal underscore names, parsing helpers, cache formats and constructor
arguments not documented here are outside this boundary.

The public model types are `Finding`, `Evidence`, `Kind`, `Surface`, `Risk`,
`RiskLevel`, and `ScanResult`; configuration uses `ScanConfig` and `ConnectorSpec`.
`SetupError` is exported for applications that handle engine setup failures.
Use named fields and `to_dict()` / `to_json()` for serialization. Reports contain
sensitive inventory; do not print them into unrestricted application logs.

## CLI and report compatibility

The [command reference](../reference/cli.md) defines the supported commands.
Machine integrations should use JSON and exit codes, never parse terminal table
layout, progress messages or English diagnostic text.

| Exit | Candidate contract |
|---|---|
| 0 | Complete for the selected scope and configured coverage policy |
| 1 | Setup, configuration, input or output failure |
| 2 | Complete result met an explicitly configured finding or drift threshold |
| 3 | Incomplete scan, or a comparison whose scope/evidence is insufficient |

Existing readers must ignore unknown optional JSON fields. Changes to required
fields, field types, identity semantics, scope comparability or exit-code
meaning require an explicit migration. New detector results, risk adjustments
and signature content may change with security fixes; they are not a promise
that rescanning different versions produces identical findings.

The contract regressions in `tests/unit/test_public_api_contract.py` exercise a
real local scan, required JSON fields, the supported imports, setup-error
propagation and incomplete-over-threshold exit precedence.

## Before declaring 1.0

- Independently review the final CLI and public API contract and migration notes.
- Run contract tests, all supported Python/platform CI jobs, connector coverage,
  package installation, security audits and the retained evaluation gates.
- Record live tenant acceptance for the deployment claims actually made.
- Rehearse release verification with the exact wheel, sdist, SBOM and attached
  provenance, and verify the manual publication gates.
- Resolve or explicitly disclose remaining compatibility breaks, incomplete
  scan causes and unsupported environments.

The maintainer records the reviewed revision and acceptance evidence before
changing the version or development-status classifier. A green test run alone
does not close these gates.
