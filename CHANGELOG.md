# Changelog

One summary per release. Detailed implementation history is maintained in the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md);
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
explain operator migrations. Earlier per-change entries are preserved in the
[change-history archive](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-detail.md).

## Unreleased

Current source adds bounded staged-file hooks, readiness and remediation guidance,
offline terminal triage, a candidate public API contract, a pinned benchmark
companion and verified release attachments. Signature loading uses faster native
event parsing when available while retaining bounded Python construction.
Other changes include evidence-based app attribution and executable-tool provenance,
structural workload inventory, per-root coverage budgets and clearer incomplete
scan diagnostics, bounded credential handling, refreshed dependency locks,
reproducible benchmark tooling and repository hygiene. These changes are not
published or tagged; install a reviewed commit. Detection was tuned using the
2026-10-11 ShadowBench estate errors, including Wudpecker and Tactiq name/domain
rules (benchmark-derived), so later runs on that estate are in-sample.

Correlation group disclosures now stay within verified scope partitions and
reflect only retained findings. YAML integrity defects preserve generic image
inventory while keeping scans incomplete, and ordinary reference URLs alone no
longer flag MCP tool poisoning. Dispatch proof caching remains bounded and
respects import shadowing; scan summaries share incomplete-reason aggregation.
A diff-scoped scan under Git older than 2.45 names that requirement instead of
asking whether the ref is valid, the example Falco rules emit the namespace and
pod the eBPF reader needs, and the release and migration notes cover the
attribution, correlation-group and dependency-floor changes.
Report readers
accept a newer scanner's slug-shaped coverage-gap reason instead of refusing
the report; forged values stay refused and the write path stays strict.

## 0.1.2 — 2026-10-08

Correct the production publication gate to query the fully qualified release tag
and verify it resolves to the reviewed commit. Preserve immutable prior tags and
TestPyPI rehearsal evidence.

## 0.1.1 — 2026-10-08

Initial release preparation: nine-surface AI discovery, inventory reconciliation,
security-sensitive output handling, CI gates and Trusted Publishing. See the
archived change history for individual hardening changes and known limits.
