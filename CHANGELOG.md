# Changelog

One summary per release. Detailed implementation history is maintained in the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md);
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
explain operator migrations. Earlier per-change entries are preserved in the
[change-history archive](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-detail.md).

## 0.1.3 — 2026-11-20

- JSON is decided by its structure, not its bytes: a data file with a
  repeated key (a provider catalog, an editor grammar) is one budgeted gap
  when neither reading of the key holds an MCP server table, a JSON Schema
  that describes an `mcp_servers` field is not a server table, and an
  oversize JSON file of up to 8 MiB is parsed to decide whether it is
  blinding. Manifests, lockfiles and agent configuration still fail closed.

- Fewer false exit 3s from unparsed input: a Continue `uses:` block reference
  is an MCP server finding, an empty manifest or MCP configuration is a note,
  and unrendered template source (a file under a `{{cookiecutter...}}`
  directory, or one that parses once its Jinja placeholders are filled in) is
  one partial gap charged to the coverage budget instead of failing the scan.

- Release-evidence attachment now finds the maintainer's draft release, which
  `releases/tags/{tag}` never returns; the TestPyPI smoke test runs outside the
  checkout so it exercises the installed wheel.

- Preserve notebook import binding when a multiline string contains magic-like
  command text; keep string-span protection isolated to each code cell, and do
  not let quotes in shell or magic lines open Python strings.

certifi 2026.10.19 removes the `emSign ECC Root CA - G3` root, whose revoked
intermediates had compromised keys (GHSA-6q48-6c7w-9gw2), from every lock.

The weekly discovery-benchmark gate compares against the companion results
directory its workflow names (`BASELINE_RUN`, currently `2026-10-09`), so a
later results directory can no longer become the baseline by sorting last.

Expired connectors share one five-second allowance for preparing partial findings,
so repeated overruns cannot each delay the report for another five seconds.
Native eBPF sensor names no longer imply an AI destination; wrapped Hubble
destination enrichment and service-specific Google AI Private Service Connect
names are retained.

Host inventory preserves Jan and LM Studio Windows install-directory context
and no longer treats relative home-like or traversal paths as home model stores.

Malformed GCP list responses, pagination limits, invalid Okta grants and conflicting
Entra permission labels now record explicit incomplete categories, independent of
resource names or diagnostic wording.

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
respects import shadowing; scan summaries share incomplete-reason aggregation.
A diff-scoped scan under Git older than 2.45 names that requirement instead of
asking whether the ref is valid, the example Falco rules emit the namespace,
pod and process name the eBPF reader needs, and the release and migration notes cover the
attribution, correlation-group and dependency-floor changes.
The sample Dockerfile uses a digest-pinned Node 22 image and an integrity-locked
CLI dependency graph, with package lifecycle scripts disabled.
Report readers
accept a newer scanner's slug-shaped coverage-gap reason instead of refusing
the report; forged values stay refused and the write path stays strict.
Automatic filesystem deadlines can reach the existing 30-minute ceiling;
media recognition, notebook automagic handling and tool-cache exclusions reduce
avoidable gaps while retaining coverage accounting and analysis limits.
Credential matching avoids repeated work inside long failed identifiers while
preserving long valid assignments and existing quotas.

## 0.1.2 — 2026-10-08

Correct the production publication gate to query the fully qualified release tag
and verify it resolves to the reviewed commit. Preserve immutable prior tags and
TestPyPI rehearsal evidence.

## 0.1.1 — 2026-10-08

Initial release preparation: nine-surface AI discovery, inventory reconciliation,
security-sensitive output handling, CI gates and Trusted Publishing. See the
archived change history for individual hardening changes and known limits.
