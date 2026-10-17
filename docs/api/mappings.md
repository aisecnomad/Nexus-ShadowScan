# Threat and control mappings

The mappings package relates each finding to entries of packaged, edition-qualified
catalogs. Threat references (the OWASP Top 10 for LLM Applications and for Agentic
Applications, MITRE ATLAS and the CSA MAESTRO layers) are exported as
`metadata.threats`, and control references (NIST AI RMF, ISO/IEC 42001, the EU AI Act
and AIUC-1) as `metadata.controls`. Each is a sorted list, left out when empty. The
[threat and control mappings](../concepts/mappings.md) guide lists the catalogs, the
rule format and where each output shows the references.

## How references are derived

A rule's `when` condition reads the finding's tags, capabilities, kind, surface,
shadow status and owner, its autonomy floor and oversight (`metadata.autonomy`), its
registry reconciliation status and the EU AI Act risk class its registering
Capability Card declares. Every key must hold, and a list matches when it shares any
value with the finding. An unknown shadow status (no inventory supplied) matches
neither `shadow: true` nor `shadow: false`, and malformed metadata counts as absent.
For example, the `declared-high-risk` rule (`declared_risk_class_any: [high]`)
references EU AI Act Articles 12, 14 and 26 only for a registered finding whose card
declares the `high` class: ShadowScan cannot tell whether a system is high-risk and
does not verify the declaration.

`Finding.to_dict` derives both keys from the finding's own state on every export and
drops any value the finding carried; `Finding.from_dict` discards them, together with
the removed `metadata.compliance` key (`DERIVED_METADATA_KEYS`). References therefore
never feed identity, risk, diff state, merging or the incremental cache, and a report
that is read back and exported again gets the references of the installed catalogs,
not those it was written with.

## Edition-qualified references

A reference is `<prefix>:<entry>`, and a catalog's prefix must be
`<framework>-<edition>`, for example `owasp-llm-2026:LLM03` or `eu-ai-act-2024:Art.14`.
Entry numbers change between editions, so a new edition gets a new prefix and a
reference cannot outlive the edition it was written for.

## Validation and limits

`load_mappings` validates the packaged catalogs and rules once per process and raises
`MappingCatalogError` listing every problem; `python -m shadowscan.mappings.validate`
runs the same checks and exits 1 on a problem. The scanner reads only the packaged
data.

The rules are author mappings and have not been independently reviewed. A reference
says a finding is evidence relevant to an entry, not that a control applies or is
met; [`shadowscan.controls`](controls.md) groups the control references per control
for `shadowscan controls`.

::: shadowscan.mappings
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
