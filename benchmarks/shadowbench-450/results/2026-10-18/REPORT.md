# ShadowBench-450: unverified supplied counts, 2026-10-18

**UNVERIFIED — author-supplied adapter observations; arithmetic checks only.**
The fixture set, labels, adapter/scorer sources and per-case predictions were
not supplied. The submitter states that vendor binaries were not run. Product
names and versions below are reported adapter targets, not tested binaries.
These counts do not establish detection performance, rankings or recommendations.

The submission reports 450 cases on nine surfaces, 268 positive finding keys,
91 near-misses and 118 controls. The underlying corpus and those labels have
not been verified. This is separate from the existing [ShadowBench cases](../../../shadowbench/cases/README.md)
and [estate](../../../shadowbench/estate/README.md) tracks and cannot be compared
with them.

## Supplied aggregate counts

Rows are alphabetical by adapter label. “In scope” is the submitter's scope
selection, not a verified assessment of the named product's coverage.

<!-- supplied-counts:start -->
| Adapter label | Reported target | Reported version | All-surface TP / FP / FN | In-scope TP / FP / FN |
|---|---|---|---|---|
| agent-discovery | Microsoft Agent Discovery | toolkit 3.1.1 | 96 / 0 / 172 | 96 / 0 / 11 |
| agentdiscover | DefendAI AgentDiscover | 2.9.5 | 117 / 0 / 151 | 117 / 0 / 26 |
| agentic-radar | SplxAI Agentic Radar | 0.14.1 | 43 / 0 / 225 | 43 / 0 / 22 |
| agentsonar | Knostic AgentSonar | 1.1.5 | 43 / 5 / 225 | 43 / 5 / 0 |
| ai-agent-discovery | OpenGuardrails AI Agent Discovery | 2026-10 main | 38 / 4 / 230 | 38 / 4 / 3 |
| ai-bom | Trusera ai-bom | 3.6.0 | 139 / 52 / 129 | 139 / 52 / 7 |
| nuguard | NuGuard | 0.9.15 | 96 / 0 / 172 | 96 / 0 / 3 |
| open-shadow-ai | open-shadow-ai | 0.3.0 | 99 / 0 / 169 | 99 / 0 / 7 |
| shadowscan | Nexus ShadowScan | 0.1.2 | 255 / 0 / 13 | 255 / 0 / 7 |
| vet | SafeDep vet | 1.20 | 79 / 0 / 189 | 79 / 0 / 3 |

<!-- supplied-counts:end -->

[metrics.json](metrics.json) retains these supplied counts plus their per-surface
breakdown and summarized misses/false alarms. No raw case-level observation is
available to check whether a reported TP, FP or FN was correctly assigned.

The original rankings, grades, intervals and product recommendations have been
withdrawn. [manifest.json](manifest.json) binds the retained counts to the
original submission's commit and file digests. See the [archive README](../../README.md)
for the arithmetic-only validator and the evidence required for reproducibility.
