# Changelog

One summary per release. Detailed implementation history is maintained in the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md);
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
explain operator migrations. Earlier per-change entries are preserved in the
[change-history archive](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-detail.md).

## Unreleased

The optional live DNS snapshot enhancement now has a scoped design and
acceptance plan; an explicit regression guards the offline network boundary.
Live DNS collection and snapshot replay remain unimplemented (#210).

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
respects import shadowing; scan summaries share incomplete-reason aggregation. Report readers
accept a newer scanner's slug-shaped coverage-gap reason instead of refusing
the report; forged values stay refused and the write path stays strict.

Ordinary repositories finish complete more often: binary media headers,
a ReDoS-bounded inline-credential pattern, a filesystem deadline sized by entries
and bytes, IPython automagic, `.hypothesis` exclusion, faster built-in pack
loading, unparsed-input triage, unclosed credential calls and dangling-link
descriptions. `shadowscan code --preflight` also lists the static coverage gaps
a full scan would record, `--max-file-size` sets the size limit, and exit 3
prints per-reason remediation with an incomplete-scans guide. The command line
and public Python API are recorded as stability snapshots checked for drift.

## 0.1.2 — 2026-10-08

Correct the production publication gate to query the fully qualified release tag
and verify it resolves to the reviewed commit. Preserve immutable prior tags and
TestPyPI rehearsal evidence.

## 0.1.1 — 2026-10-08

Initial release preparation: nine-surface AI discovery, inventory reconciliation,
security-sensitive output handling, CI gates and Trusted Publishing. See the
archived change history for individual hardening changes and known limits.
