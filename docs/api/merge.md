# Merge

The merge module deduplicates findings that the same connector observes more than once in the
same run, or across runs when findings are combined with `shadowscan merge`.

## When findings merge

Two findings merge when they share the same `id` (their content-addressed identity). This
happens in two scenarios:

1. **Within a scan** — a connector yields the same logical finding twice (e.g. a GitHub
   connector that paginates across forks and sees the same repository twice).
2. **Across scans** — `shadowscan merge` unions two or more JSON reports; findings with the
   same identity from different reports are merged into one.

## What survives a merge

| Field | Rule |
|-------|------|
| `evidence` | Union of all evidence items |
| `frameworks` / `model_providers` | Union |
| `tags` / `capabilities` | Union |
| `first_seen` | Earliest across all observations |
| `last_seen` | Latest across all observations |
| `metadata` | First observation's value wins per key (except keys listed in `MERGE_METADATA_KEYS`) |
| `kind` | Highest-precedence classification: `agent` > `service-identity` > `oauth-grant` |
| `resource_type` | Paired with `kind`; tie-broken lexically for stability |
| `metadata.autonomy` | Re-classified from the merged finding, then widened to admit all sources |

## Fleet merge

`shadowscan merge` is a thin wrapper that calls [`fleet`](fleet.md) logic to combine entire
reports, including findings from different machines. Findings from different machines never
merge with each other: the endpoint-label prefix in their `resource` keeps them distinct.

::: shadowscan.merge
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
