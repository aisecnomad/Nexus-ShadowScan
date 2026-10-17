# Fleet merge

The fleet module combines ShadowScan JSON reports from multiple machines or multiple scan runs
into a single unified report. The output is a valid `ScanResult` that can be rendered by any
reporter, diff'd against a baseline or fed to the dashboard.

## What merges and what stays separate

Findings merge when they share the same `id` (the same logical object seen by the same
connector). Findings from **different machines** never merge — the endpoint-label prefix that
each connector adds to `resource` keeps them distinct even when the same tool is installed on
several hosts.

Everything else follows the same rules as [within-scan deduplication](merge.md):

- Evidence, frameworks, model_providers, tags and capabilities are unioned.
- `first_seen` keeps the earliest timestamp; `last_seen` keeps the latest.
- The first source's metadata value wins per key.
- `kind` is resolved by precedence: `agent` > `service-identity` > `oauth-grant`.
- `metadata.autonomy` is re-classified from the merged finding and then widened to admit
  whatever any source's validated interval admits.

## Registration and shadow status

Registration counts only from sources that ran with an inventory (`inventory_present: true`).
A finding is **shadow** when any inventory-running source found it unregistered; it is
**registered** only when all such sources matched it. Sources without an inventory contribute
evidence and technology signals but do not affect shadow status.

A merged finding that is shadow or unassessed loses its declared governance block
(`metadata.declared_governance`). If registered sources disagree on the declared governance
for one agent, the merge is refused for that finding.

::: shadowscan.fleet
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
