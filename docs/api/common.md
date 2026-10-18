# Connector helpers

The `connectors.common` module holds the helpers connectors share to turn signature matches
into evidence on a `Finding`. It also holds `merge_duplicate_metadata()`, through which
`shadowscan.merge` folds the metadata of repeated observations of one finding together.

## Matching

`name_matches()`, `domain_matches()`, `scope_matches()` and `model_matches()` run the
`SignatureIndex` over display names, URLs or hosts, permission scopes and model ids.
`blob_matches()` runs code, domain and environment-variable signatures over free text, plus
credential signatures with `secrets=True`. Each returns de-duplicated `Match` objects.

### `apply_matches()`

Attaches matches to a finding as `Evidence` and returns the number of agent-indicator
matches. A match takes one of these paths:

- **Established**: a match that is not an ambiguous name (with the default `establish=True`)
  adds the signature's tags and capabilities. A technology signature also joins `frameworks`,
  a `provider` signature joins `model_providers` and a `policy` signature becomes a tag; a
  `heuristic` signature adds nothing more. The generic AI-name signature
  (`identity-app.generic-ai-name`, which matches words such as "Copilot") adds the tag
  `ai-name-hint` instead of a technology.
- **Ambiguous name**: a name signal marked `ambiguous` (for example "Gemini", which is also a
  cryptocurrency exchange) never establishes anything. Its weight is capped at 0.2, the finding
  is tagged `ai-name-hint`, and the signature is listed under `metadata.potential_frameworks`
  or `metadata.potential_providers`.
- **Corroborated name**: once a non-name signal has established the same product on the
  finding, a later ambiguous name keeps its full weight. It adds no tag, capability or second
  agent indicator.
- **Evidence only**: with `establish=False` (a code pattern without the library's import or
  dependency, or a mention too weak to establish), a match that is not an ambiguous name keeps
  its weight but adds no technology, tag, capability or agent indicator. A technology or
  provider signature is listed as potential until an establishing match removes it.

At most `max_evidence_per_signature` (default 12) evidence items are kept per signature and
signal type, and credential values are redacted.

### `classify_permissions()`

Records the scopes in `permissions` and applies scope signatures at half weight. The
`policy.privileged-scopes`, `policy.data-access-scopes` and `policy.llm-access-scopes`
signatures tag the finding with their ids.

### `finalize()`

Recomputes confidence and promotes a `framework-usage` finding with an agent indicator to
`agent`. For an app that `assess_app()` (in `shadowscan.connectors.identity.common`) assessed
and that has no AI attribution, it bounds the app's non-AI observations. Attribution means a
framework, a model provider, the tag `policy.llm-access-scopes`, `entra-agent-identity` or
`registry-record`, or registry-record evidence. The bounded observations, including an
ambiguous name, become one correlated group (`confidence_group: unattributed-app`) with each
weight capped at `UNATTRIBUTED_APP_MAX_WEIGHT` (0.35). A generic AI-name hint stays separate.
See [unattributed applications](../connectors/identity.md#unattributed-applications).

## Placeholder credentials

`placeholder_reason()` returns `template`, `placeholder-word` or `low-entropy` for a
credential-looking value that is a documentation placeholder, and None otherwise. The value
is a placeholder when it has a template marker (`<...>`, `${...}`, `{{...}}`), a placeholder
word (REPLACE, YOUR, EXAMPLE, … and equivalents in several languages) or a fill run such as
`xxxx` or an ellipsis, or a low-entropy body of at least eight characters after the provider
prefix (`00000000`, `1234567890`). For an assignment
(`NAME=value`) only the value is judged. A placeholder never becomes a `secret` finding:
`blob_matches()` drops placeholder credential matches, and the `code.filesystem` connector
reports them as low-weight `example-credential` evidence with the value redacted.

::: shadowscan.connectors.common
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
