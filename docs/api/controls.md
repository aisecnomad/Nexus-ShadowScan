# Control evidence

The controls module powers `shadowscan controls`: a cross-reference between discovered findings
and the control items of recognised AI governance frameworks. It tells an operator which
specific controls they have evidence for, how complete that evidence is, and what the
highest-risk examples are.

## Supported control catalogs

| Catalog | Coverage |
|---------|---------|
| **NIST AI RMF** | Govern, Map, Measure, Manage functions |
| **ISO/IEC 42001** | AI management system clauses 4–10 |
| **EU AI Act** | High-risk system requirements, articles 9–17 |
| **AIUC-1** | AI Use Case conformity certificate requirements |

## How control evidence is computed

For each control in the selected catalog(s), the module counts findings whose
`metadata.threats` or `metadata.controls` reference lists include that control's identifier.
The references are derived from the author mappings in [`mappings`](mappings.md) and are
recomputed from the findings at reporting time — they are never stored in the JSON report.

## Completeness

A control reads "not observed" only when:

1. Every report in the input is complete (no connector errors, no incomplete collections), and
2. No finding could reference the control through a fact the reports do not hold (shadow status
   without an inventory run, a risk class that no card declares).

Otherwise the control reads "unknown". This prevents false reassurance: an incomplete scan
never tells you a control has no evidence.

## Important caveat

Control references are **evidence references**, not compliance determinations. The presence of
a finding that references a control does not mean the control is met or even that it applies.
There is no score, no pass/fail and no compliance claim.

::: shadowscan.controls
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
