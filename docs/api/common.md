# Connector helpers

The `connectors.common` module contains the helpers that translate raw signature matches into
`Finding` objects. Connectors never hard-code product knowledge; they pass observations to
these functions and receive scored evidence in return.

## Core functions

### `apply_matches()`

Takes an iterable of `Match` objects from the `SignatureIndex` and adds them to a `Finding` as
`Evidence` items. It handles the four match outcomes:

- **Established** — a non-ambiguous match that identifies a framework, provider or product. Sets
  `frameworks` / `model_providers` and any tags or capabilities declared by the signature.
- **Ambiguous** — a name match that fires on a pattern common enough to generate false positives
  (e.g. "Copilot"). Adds `ai-name-hint` and a fractional weight; does not set `frameworks`.
- **Corroborated** — an ambiguous match that a second, non-ambiguous signal confirms. Treated as
  established.
- **Potential** — a domain or name match that is noted but not yet corroborated; stored in
  `metadata.potential_frameworks` for display.

### `classify_permissions()`

Applies the identity-surface `policies.yaml` signatures to an OAuth scope list. Fires
`policy.llm-access-scopes`, `policy.data-access-scopes`, `policy.privileged-scopes` and related
tags when the scope set matches a policy.

### `name_matches()` / `domain_matches()`

Query the `SignatureIndex` for name and domain signals respectively, returning `Match` objects
for `apply_matches()` to consume.

### `finalize()`

Called after `assess_app()` in identity connectors. Caps the total evidence weight for apps that
have no confirmed AI attribution (no `frameworks`, no `model_providers`, no strong AI tags) at
`UNATTRIBUTED_APP_MAX_WEIGHT = 0.35`, preventing low-signal apps from reaching the reporting
threshold through weight accumulation alone.

## Placeholder credentials

`placeholder_reason()` identifies credential values that are documentation placeholders rather
than live secrets: template markers (`<...>`, `${...}`, `{{...}}`), placeholder words
(REPLACE, YOUR, EXAMPLE, …) and low-entropy fills (`xxxx`, `1234567890`). Placeholders are not
redacted and do not contribute to secret findings.

::: shadowscan.connectors.common
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
