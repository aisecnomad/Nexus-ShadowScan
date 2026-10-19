# ShadowBench-450: unverified aggregate archive

**UNVERIFIED — author-supplied adapter observations.** This directory preserves
aggregate counts submitted in [PR #269](https://github.com/aisecnomad/Nexus-ShadowScan/pull/269).
It contains no executable benchmark, fixtures, labels, adapter source or per-case
predictions. The submitter states that vendor binaries were not run. The named
products and versions identify the submitter's intended adapter targets; they
are not verified executions of those products.

The submission reports 450 cases, 50 on each of nine surfaces, with 268 positive
finding keys, 91 near-misses and 118 controls. These are supplied counts, not
independently checked corpus facts. Finding-key counts need not sum to case
counts. Public-repository anchors were asserted but were not supplied.

The original submission also stated that the ShadowScan maintainer authored
both its adapter and the labels. Neither adapter fidelity nor independence,
label quality, detection results or field performance can be established from
this archive. It supports no product ranking, letter grade, recommendation or
comparison with the [ShadowBench cases and estate tracks](../shadowbench/README.md).
Those tracks' existing result files are unchanged.

## Preserved observations

The [archive report](results/2026-10-18/REPORT.md) lists the reported aggregate
counts in adapter-label order. [metrics.json](results/2026-10-18/metrics.json)
also retains the supplied per-surface counts, scope declarations and summarized
misses/false alarms. A declared in-scope count is not a validated scope decision.

Rankings, tiers, grades, accuracy estimates, bootstrap intervals and product
recommendations have been withdrawn. Aggregate confusion counts alone cannot
reproduce a case bootstrap. [manifest.json](results/2026-10-18/manifest.json)
records the original submission commit and file digests so the correction is
traceable; its hashes establish content identity, not truth of the observations.

## Arithmetic check

From the repository root:

```bash
python -m tools.shadowbench450_archive
```

This local, data-only check verifies count consistency, preservation, report
agreement and the unverified status. It makes no network requests and does not
execute fixtures, adapters or third-party products. A pass means **arithmetic-only
verification**, never verified detection performance.

## Evidence needed for a reproducible evaluation

Before publishing benchmark conclusions, retain and review:

- All fixtures, stable case IDs and pinned source anchors with provenance.
- Labels and their evidence, including near-misses, controls and scope mappings.
- Adapter and scorer source, immutable revisions and documented limitations.
- Per-case predictions, execution receipts and a reproducible environment/command.
- Any uncertainty calculation's inputs and method; publish a fresh held-out
  evaluation separately from observations used to develop the adapters.

Product-performance claims additionally require executions of the actual
products at pinned revisions, with outputs and failures retained. No missing
artifact or successful run is inferred by this archive.
