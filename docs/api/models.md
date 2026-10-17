# Models

The models module defines the core data types that every part of ShadowScan shares: connectors,
the engine, reporters and the CLI all speak the same `Finding` vocabulary.

## Finding

A `Finding` represents one AI agent, service identity or OAuth grant discovered on one surface by
one connector. Its key fields are:

- **`surface`** — one of `code`, `identity`, `gateway`, `lowcode`, `saas`, `cloud`, `endpoint`,
  `network`, `runtime`.
- **`kind`** — classification: `agent`, `service-identity` or `oauth-grant`.
- **`confidence`** — 0–1 score from accumulated evidence weights.
- **`risk`** — explainable risk assessment (see [`Risk`](risk.md)).
- **`frameworks`** — AI frameworks detected (e.g. `framework.langgraph`, `framework.autogen`).
- **`model_providers`** — model providers in use (e.g. `provider.openai`, `provider.aws-bedrock`).
- **`tags`** — capability and classification tags (e.g. `tool-use`, `machine-identity`,
  `policy.llm-access-scopes`).
- **`evidence`** — ordered list of `Evidence` items, each with a signal name, description,
  location and weight.
- **`shadow`** — `True` when the finding is not registered in the sanctioned inventory.

## Redaction and sanitization

`Finding` objects carry an internal clean-state digest. After `sanitize()` has run, assigning
any field invalidates the digest so the next serialization re-sanitizes. Reporters always call
`sanitize()` before rendering; a finding whose sanitization fails is excluded from the output
and recorded as a warning. Resource identifiers, owner names, file paths and credential-looking
strings are replaced by `[redacted]` in evidence descriptions.

## ScanResult

`ScanResult` wraps the complete output of one scan: the list of findings, the `ScanStats`
(examined records, errors, connector coverage), the `ScanConfig` that produced it, and the
exit code. Reporters consume a `ScanResult`; the engine returns one.

::: shadowscan.models
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
