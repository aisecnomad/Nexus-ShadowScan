# Control evidence

The controls module builds the `shadowscan.control-evidence/v1` document that
`shadowscan controls` renders as Markdown, CSV or JSON. It merges one or more JSON
scan reports as `shadowscan merge` does and, for every entry of the selected control
catalogs, counts the findings whose control references name it, split by risk level,
with up to 10 of the highest-risk findings as examples. The
[control evidence report](../operations/controls.md) guide describes the command, its
output formats and its exit codes.

## Control catalogs

Every packaged control catalog is reported unless `--framework` names some, by prefix
(one edition) or by framework id (every packaged edition). A name that matches no
control catalog raises `ControlSelectionError`.

| Prefix | Catalog | Entries |
| --- | --- | --- |
| `aiuc-1-2026q2` | AIUC-1 | Domains A to F and requirement D003 |
| `eu-ai-act-2024` | EU AI Act, Regulation (EU) 2024/1689 | Articles 12, 14, 15, 26 and 50 |
| `iso-iec-42001-2023` | ISO/IEC 42001:2023 Annex A | A.3.2, A.4.2, A.6.2.6, A.6.2.8, A.9.2 and A.10.3 |
| `nist-ai-rmf-1.0` | NIST AI Risk Management Framework 1.0 | 11 subcategories of the GOVERN, MAP, MEASURE and MANAGE functions |

## How references are counted

The module does not read `metadata.controls` from the reports. It evaluates the
packaged control rules of [`shadowscan.mappings`](mappings.md) against every merged
finding again, so the counts follow the installed catalogs. Each finding's shadow
status is first recomputed from the source reports: shadow when a report reconciled
with an inventory says so, registered when every report that holds it was reconciled
and says so, and unknown otherwise. A report that `shadowscan merge` produced is refused with `ValueError`;
pass the source reports instead. An example referenced only through an EU AI Act risk
class declared in a Capability Card has the basis `declared`, any other `observed`.

## Completeness

Every catalog entry gets one of the `EVIDENCE_STATUSES`. A control that findings
reference reads `referenced`, or `referenced (scan incomplete)` when the evidence is
incomplete, and a control that no packaged rule references reads `not mapped`. Any
other control reads `not observed` only when every report is complete and no finding
could reference it through a fact the reports do not hold (a shadow status without an
inventory, a risk class no card declares); otherwise it reads
`unknown (scan incomplete)`, `unknown (inventory not supplied)` or
`unknown (risk class not declared)`. The guide's
[evidence status](../operations/controls.md#evidence-status) table explains each value.

A report is complete only when its summary says so, no connector record has errors,
was skipped or is incomplete, and its summary counts match its findings array. One
incomplete report makes the whole document incomplete: `shadowscan controls` still
writes the output, marked incomplete, and exits 3.

## Evidence, not compliance

Control references are evidence references written by the project's author and not
independently reviewed. A finding that references a control does not mean the control
is met or applies, and the document has no score.

::: shadowscan.controls
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
