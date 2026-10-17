# Fleet merge

The fleet module combines ShadowScan JSON reports from several machines or scans into one report.
`merge_reports()` backs `shadowscan merge`, and `shadowscan dashboard` when it is given several
reports. It returns a `ScanResult` that any `--format` renders. `report_result()` reads a single
report, a scan or an earlier fleet merge, as a source is read, without merging it again.

## What merges and what stays separate

Findings with the same `id` merge through [`merge()`](merge.md), exactly as repeated observations
do inside one scan. A report that reuses an id for a finding whose own fields describe another
identity is refused rather than merged. Findings from `shadowscan endpoint` scans of different
machines stay separate because the endpoint label (`endpoint:<hostname>` by default, or `--label`)
prefixes every resource. Machines that share a host name and home directory, such as clones of
one VM image, merge as one machine unless each gets its own `--label`.

After `merge()`, each merged finding:

- lists its source reports in `metadata.merged_from`;
- keeps the highest source risk (`metadata.fleet_risk_aggregation: maximum-source-score`);
- has `metadata.autonomy` classified again from the merged finding and widened to admit whatever
  any source's valid interval admits;
- carries no `metadata.llm_triage` verdict from a source.

## Registration and shadow status

Registration counts only from sources that reconciled against an inventory
(`inventory_present: true`). A finding is **shadow** when any such source found it unregistered,
**registered** when such sources matched it to one agent, ambiguous (shadow, with
`registry_match_reason: ambiguous-resource-approval`) when they matched it to different agents, and
unassessed (`shadow: null`) when no such source reported it. The `shadow` and `registry_match` of a
source without an inventory are cleared; its evidence still merges.

A merged finding that is shadow or unassessed loses its declared governance block
(`metadata.declared_governance`). If the sources of a registered finding carry different declared
governance, the whole merge is refused rather than keeping the first source's.

## Completeness and comparison

A source that is incomplete, or whose summary counts do not match its findings, adds an
`engine.fleet` error, so the merged report is incomplete and `shadowscan merge` exits 3. The merged
`collection_scope` is comparable with `shadowscan diff` only when every source is complete and
carries a comparable scope; its fingerprint is then derived from the sources' fingerprints.
`collection_scope.fleet` (`shadowscan.fleet-merge/v2`) lists each source. Every refusal raises
`ValueError` (`shadowscan merge` exits 1), including a report with another finding identity schema,
malformed autonomy or declared governance metadata, or more than 10,000 reports.

::: shadowscan.fleet
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
