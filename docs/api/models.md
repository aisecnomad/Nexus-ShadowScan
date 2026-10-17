# Models

The models module defines the data types that connectors, the engine and the reporters share.
Everything ShadowScan discovers is normalised into a `Finding`: one thing that behaves like, or
enables, an AI agent on one surface, with the evidence that led to it.

## Finding

Its key fields are:

- **`surface`**: a `Surface`, one of `code`, `identity`, `gateway`, `lowcode`, `saas`, `cloud`,
  `endpoint`, `network`, `runtime`.
- **`kind`**: a `Kind`, one of `agent`, `framework-usage`, `mcp-server`, `agent-config`,
  `oauth-grant`, `service-identity`, `token`, `gateway-caller`, `workflow`, `bot-app`,
  `cloud-resource`, `iam-grant`, `secret`, `infra`, `ai-app`, `local-model`, `network-contact`,
  `runtime-process`.
- **`confidence`**: 0 to 1, the noisy-OR of the evidence weights with each correlated group
  counted once (`recompute_confidence`). `likelihood` is its heuristic bucket (`strong` from
  0.85, `likely` from 0.6, `possible` from 0.3, otherwise `weak`), not a verification state.
- **`risk`**: a `Risk` with a `score` from 0 to 100, its `level`, the `factors` behind it and a
  `danger_score`; see [Risk](risk.md).
- **`frameworks`** and **`model_providers`**: signature ids, such as `framework.langgraph` or
  `provider.aws-bedrock`.
- **`tags`**: signature tags and classification tags, such as `machine-identity`,
  `ai-name-hint` or `policy.llm-access-scopes`.
- **`evidence`**: a list of `Evidence` items, each with a `signal`, `description`, `location`,
  `snippet`, `weight` (0 to 1), `signature` and `attributes`.
- **`shadow`**: `None` when no inventory was supplied, `True` when the finding matches no
  inventory entry, `False` when it matches one (`registry_match` names it).
- **`id`**: `ss-` and 16 hexadecimal digits of a SHA-256 over the finding's identity fields,
  under the identity schema `shadowscan.finding-identity/v2`.

## Sanitization

`Finding` and `Evidence` sanitize themselves when they are created, and `sanitize()` runs again
before every export: `to_dict()`, `ScanResult.summary()` and every reporter call it. A completed
pass keeps a digest of the sanitized state together with the redaction policy in force
(`policy_token()`), so a later pass over unchanged state returns at once. Assigning a different
value to a field drops the digest, and an in-place change through a container or a replaced
redaction rule no longer matches it, so each of these gets a full pass.

If redaction would rewrite the fields that identify a finding (its connector, resource type or
identity discriminator, or any identity field when the id was not derived from them),
`sanitize()` raises `SanitizationLimitError`, as it does for a value past the sanitizer's limits.
The engine omits such a finding and records the error
`finding omitted: sanitization safety limit exceeded`, which marks the scan incomplete (exit 3);
see [Redaction](redaction.md#safety-limits).

## ScanResult

`ScanResult` holds the findings and one `ScanStats` per connector (objects examined, errors,
warnings, coverage and the reasons a scan is incomplete), with `started_at`, `finished_at`,
`version`, `inventory_size`, `inventory_present` and `collection_scope`. `complete` is true only
when there is at least one `ScanStats` and none has errors, was skipped or is incomplete; the
CLI exits 3 otherwise. `to_json()` raises `ValueError` rather than publish a NaN or infinite
value. `Engine.run()` returns a `ScanResult`, and the reporters render one.

::: shadowscan.models
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
