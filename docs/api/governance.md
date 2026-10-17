# Declared governance

The governance module records operator-declared facts from **Agent Capability Cards** in each
matched finding. These facts are things the scanner cannot observe from the environment: the
EU AI Act risk class the operator assigned, the intended purpose, oversight measures, standards
certifications and regulatory scope.

## What can be declared

A `schema_version: 2` Capability Card may carry a `governance:` block with the following
optional fields:

| Field | Description |
|-------|-------------|
| `eu_ai_act_risk_class` | `unacceptable`, `high`, `limited`, `minimal` or `exempt` |
| `intended_purpose` | Free-text description of what the agent is designed to do |
| `oversight_measures` | List of human oversight controls in place |
| `aiuc1_certificate` | Reference to an AIUC-1 conformity certificate |
| `iso_42001_scope` | Whether the system is within an ISO/IEC 42001 management system scope |

## Important limitations

ShadowScan **never infers, checks or scores** governance declarations. They are recorded
verbatim from the card and labelled "declared" in the report. A declared `eu_ai_act_risk_class`
only influences which control references (NIST AI RMF, ISO/IEC 42001, etc.) are shown for that
finding.

Governance declarations require that the finding be matched to a registered inventory entry.
An unmatched (shadow) finding and a finding from a scan without an inventory both have
`metadata.declared_governance` set to `None`.

::: shadowscan.governance
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
