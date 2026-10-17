# Risk

The risk module produces an explainable risk score for every finding. Scores are additive: the
final number is the sum of named factors, each recorded as a `RiskFactor` so the report can
explain exactly why something is rated critical.

## Score model

The score is computed from four dimensions, then scaled by confidence and clamped to 0–100:

| Dimension | What it measures |
|-----------|-----------------|
| **Capability** | What the agent is and what it can do: kind, frameworks, capabilities (tool-use, code-execution, …) |
| **Reach** | What it can access: OAuth scopes, cloud permissions, network access, data-access policies |
| **Governance** | Whether it is registered, owned and approved in the sanctioned inventory |
| **Shadow penalty** | Additional weight when a finding is unregistered (shadow) |

## Risk levels

Scores map to levels as follows:

| Level | Score |
|-------|-------|
| **critical** | ≥ 75 |
| **high** | ≥ 50 |
| **medium** | ≥ 25 |
| **low** | > 0 |

## Danger score

`danger_score` excludes governance factors. This lets triage rank what an agent *can do*
independently of whether anyone approved it, useful for comparing registered and unregistered
agents with equivalent capabilities.

## Risk policies

A `RiskPolicy` (configured under `options.risk`) overrides individual factor weights and can
base the level on `danger_score` alone. This is useful when governance factors should not
elevate the level of an otherwise low-capability agent.

::: shadowscan.risk
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
