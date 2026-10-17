# Merge

The merge module folds repeated observations of one finding into one. The engine calls `merge()`
on every scan's findings, and [`shadowscan.fleet`](fleet.md) calls it when `shadowscan merge` or
`shadowscan dashboard` combines several reports.

## When findings merge

Two findings merge when they share the same `id`. `Finding.compute_id()` derives it from the
identity schema, surface, connector, provider, account, region, resource and identity
discriminator, so only observations of one object by the same connector share an id. The kind is
not part of it.

## What survives a merge

| Field | Rule |
|-------|------|
| `evidence` | Union, one item per signal, location and description |
| `frameworks`, `model_providers`, `capabilities`, `tags`, `permissions`, `models` | Union |
| `owner` | The first observation's, or a later one's when the first has none |
| `first_seen` / `last_seen` | The earliest / latest value that is set |
| `metadata` | The first observation's value of each key, except the keys `merge_duplicate_metadata()` combines: `variable_names`, `runtime_observations` and, for gateway findings, `runtime_sources`, whose request, token and cost metrics are summed |
| `kind` / `resource_type` | Chosen as one pair: `agent` over `service-identity` over `oauth-grant` over any other kind, then the lexically greater kind and resource type. When observations disagree, `metadata.observed_kinds` and `metadata.observed_resource_types` list every value |
| `confidence` | Recomputed from the merged evidence |

`merge()` does not reclassify autonomy, risk or registration. A fleet merge sets those from all
sources after calling it; see [Fleet merge](fleet.md).

::: shadowscan.merge
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
