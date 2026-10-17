# Dashboard

The dashboard module builds the `shadowscan.inventory/v1` document that powers
`shadowscan dashboard` and the `--inventory-json` export. It turns a scan or fleet
`ScanResult` into a structured JSON summary suitable for BI tools, SIEMs and executive
dashboards.

## Document structure

`build_inventory()` produces a single JSON document with the following top-level sections:

| Section | Contents |
|---------|----------|
| **Coverage** | Per-source, per-connector collection status (`collected`, `not-collected`, `unknown`) |
| **Counts** | Total findings, by surface, by risk level, by shadow status |
| **Autonomy vs shadow** | Cross-tabulation of autonomy tier against shadow / registered status |
| **Vendor registries** | Reconciliation results against AWS, Microsoft, Google and other vendor registries |
| **Threat and control references** | Counts of findings per NIST AI RMF / ISO 42001 / EU AI Act reference |
| **Drift** | Findings that appeared, disappeared or changed since a baseline scan |
| **History** | Previous scan timestamps and finding counts |
| **AI system records** | One record per finding (title, surface, risk, autonomy, shadow status, frameworks) |

## Privacy and sanitization

Records carry no evidence snippets, evidence attributes, permissions or raw metadata. Every
finding passes its own sanitizer before appearing in the inventory document. Sources, diagnostics
and history come from report files and are sanitized here.

Credential findings (`secret` and `token` kind) are **counted** but not included as records.

## Missing data visibility

The document makes missing data explicit. A connector that did not run appears as
`not-collected`. A source from an older fleet report has `unknown` coverage. A finding whose
kind the autonomy scale describes but which has no interval is `not-classified` (never zero).
Coverage cells are stored only for the connectors a source actually ran, so the document grows
with its input, not with sources × connectors.

::: shadowscan.dashboard
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
