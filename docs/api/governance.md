# Declared governance

The governance module validates and records the facts an operator declares in the
`governance:` block of an Agent Capability Card: facts the scanner cannot observe, such as the
EU AI Act risk class the operator assigned, the intended purpose, the oversight measures in
place, an AIUC-1 certificate reference and whether the system is inside an ISO/IEC 42001
management system scope.

## What can be declared

Only a `schema_version: 2` card may carry a `governance:` block; simple inventory entries and
CSV rows cannot. Every field is optional, and a field set to null is undeclared:

| Field | Value |
|-------|-------|
| `eu_ai_act_risk_class` | `prohibited`, `high`, `limited`, `minimal`, `gpai`, `gpai-systemic` or `unknown` |
| `intended_purpose` | A nonempty string of at most 500 characters |
| `oversight_measures` | A list of at most 20 nonempty strings of at most 200 characters each |
| `aiuc1_certificate` | A nonempty string of at most 200 characters |
| `iso42001_scope` | `true` or `false` |

An unknown field, a value that breaks these rules or a `governance:` block on a card without
`schema_version: 2` makes the inventory invalid, so it fails to load and no scan runs. Error
messages name the field, never its value.

## How declarations are used

A finding that a card registers in the current run records the card's block as
`metadata.declared_governance`, with the card's agent id as `source`. A shadow finding, a
finding from a scan without an inventory and a finding registered by an entry that declares
nothing have no `declared_governance` key: reconciliation first removes any value that a
connector, a plugin, a cache entry or an earlier pass wrote. The HTML and Markdown reports show
the facts as "Declared governance (card …, not verified)".

ShadowScan never infers, checks or scores these facts. A declared `eu_ai_act_risk_class` only
selects the [declared control references](../concepts/mappings.md#declared-facts): EU AI Act
Articles 12, 14 and 26 for `high`, and Article 50 for `limited`, `gpai` or `gpai-systemic` on an
`agent`, `bot-app` or `ai-app` finding. Declared facts do not change risk scores, matching or
approval. The card format is described under
[declared governance facts](../inventory.md#declared-governance-facts).

::: shadowscan.governance
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
