# Risk

The risk module gives every finding an explainable score from 0 to 100. The score is
additive: each contribution is a `RiskFactor` with a signed weight, and the listed factors
always add up to the reported score, including the `confidence-scaling` and `bounds`
adjustments. The weights are author-chosen heuristics, not fitted to incident outcomes; see
[Severity is not an enforcement signal](../severity.md).

## Score model

`assess` sums the factors below, multiplies the sum by `0.6 + 0.4 × confidence` and bounds the
result to 0–100. [Risk scoring](../concepts/risk.md#risk) lists the default weights.

| Factors | `risk_weights` group |
|---------|----------------------|
| `kind`: base weight of the finding kind | `kinds` |
| `capability:<name>`, such as `code-exec` or `tool-use` | `capabilities` |
| `combination:<id>`: capability sets that weigh more together, such as `injection-to-execution` | `combinations` |
| `tag:<tag>`, such as `policy.privileged-scopes` or `public-ingress` | `tags` |
| `provider:<id>`: model provider signatures | `providers` |
| Governance: `shadow` and `registered` (only when an inventory is present), `no-owner`, `mcp-not-in-approved-registry` | `governance` |
| `autonomy:L<n>`: the observed autonomy floor, weight 0 by default | `autonomy` |
| `vendor-notes` and kind-specific metadata factors such as `mcp-plain-http` or `blast-radius` | not configurable |

## Risk levels

| Level | Score |
|-------|-------|
| **critical** | ≥ 75 |
| **high** | ≥ 50 |
| **medium** | ≥ 25 |
| **low** | > 0 |
| **info** | 0 |

## Danger score

`danger_score` applies the same scaling and bounds to every factor except the governance
factors, so triage can rank what a finding can do separately from whether anyone approved it.

## Risk policies

A `RiskPolicy` is built from `options.risk_weights` and `options.risk_basis`. Under
`risk_basis: danger` the governance factors weigh nothing and are omitted, so `score`, `level`
and `--fail-on` follow the danger score; the default is `combined`. Weights are integers from
-100 to 100. Unknown groups and unknown kind, capability, combination, governance and autonomy
keys are rejected; provider ids are checked against the provider signatures the engine
loads; an unfamiliar tag is accepted and logged once.

```yaml
options:
  risk_basis: combined         # or danger
  risk_weights:
    capabilities:
      code-exec: 20
    combinations:
      injection-to-execution: 15
    tags:
      scheduled: 0
    governance:
      no-owner: 15
```

::: shadowscan.risk
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
