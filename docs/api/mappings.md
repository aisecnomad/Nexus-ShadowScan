# Threat and control mappings

The mappings module maps ShadowScan findings to external threat and control references from
NIST AI RMF, ISO/IEC 42001, the EU AI Act and AIUC-1. These references appear in the JSON
report under `metadata.threats` and `metadata.controls`, and are the inputs to the
`shadowscan controls` cross-reference view.

## How mappings work

Mappings are **derived at reporting time** from a finding's surface, kind, frameworks,
capabilities, tags, risk level and declared governance. They are never stored in the JSON
report as static fields; `metadata.threats` and `metadata.controls` are in
`DERIVED_METADATA_KEYS` and are recomputed from the rest of the finding on each serialization.

This design means:

- Mappings update automatically when the packaged catalogs change without needing a re-scan.
- The same finding can reference different controls depending on its declared EU AI Act risk
  class (set in the Capability Card).
- A finding's control references reflect its actual observed properties, not a manual
  classification.

## Edition qualifiers

Some mappings are **edition-qualified**: they only apply to findings at or above a certain
autonomy tier, risk level or shadow status. For example, a control that applies only to
high-risk EU AI Act systems is gated on `eu_ai_act_risk_class: high`.

## Limitations

Mappings are authored heuristics. They establish that a finding is **evidence relevant to** a
control, not that the control applies, is satisfied or has been tested. The
[`controls`](controls.md) module makes this explicit with its completeness and "evidence
reference, not compliance determination" language.

::: shadowscan.mappings
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
