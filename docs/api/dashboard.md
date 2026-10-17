# Dashboard

The dashboard module builds the `shadowscan.inventory/v1` document behind `shadowscan dashboard`.
The HTML page renders exactly this document, and `--inventory-json` writes it for BI and SIEM
tools. `build_inventory()` takes a scan or fleet `ScanResult`, which the command reads with the
[fleet](fleet.md) module; [Fleet dashboard](../operations/dashboard.md) describes the page.

## Document structure

| Key | Contents |
|-----|----------|
| `coverage`, `sources` | Per source: completion, staleness, whether it supplied an inventory, and a status for each connector it ran (`complete`, `cached`, `incomplete` or `skipped`) |
| `diagnostics` | Connector runs that did not complete cleanly (errors, warnings, skipped or incomplete); beyond 500, the rest are counted in `diagnostics_omitted` |
| `counts` | AI systems by inventory status (`shadow`, `sanctioned`, `no-inventory`), surface, kind, provider, account, owner and risk level, with the unowned, ambiguous and excluded credential counts |
| `autonomy` | AI systems by autonomy floor (L0 to L5, `not-classified`, `not-applicable`) against inventory status, and the priority count: shadow AI systems with a floor of L4 or above |
| `registries` | Per registry type and registry id: records by reconciliation status, approved, not approved and auto-approved records, and whether every listing was complete |
| `references` | How many AI systems each [threat and control reference](../concepts/mappings.md) applies to |
| `drift` | With a baseline: the `compare_reports()` counts, drift classes, adverse classes and finding ids |
| `history` | With `load_history()`: per-report totals and drift counts for comparable consecutive reports |
| `agents` | One record per AI system: every finding that is not a credential |

Threat and control references are evidence references, not compliance determinations.

## Privacy and sanitization

Records carry no evidence snippets, evidence attributes, permissions or raw metadata. Every
finding passes its own sanitizer before it becomes a record. Sources, diagnostics and history come
from report files and are sanitized here. Credential findings (`secret` and `token` kind) are
**counted** but not included as records.

## Missing data visibility

The document makes missing data explicit. A connector a source did not run reads `not-collected`;
a source from a fleet report written before sources recorded their connector runs has `unknown`
coverage; a finding that no inventory assessed (`shadow: null`) is `no-inventory`; and a finding
whose kind the autonomy scale describes but which has no valid interval is `not-classified`, never
zero.
Coverage cells are stored only for the connectors a source actually ran, so the document grows
with its input, not with sources × connectors.

`build_inventory()` raises `ValueError` on malformed input, including a sanitizer limit. The
document's `complete` is false when the result or any source is incomplete; `shadowscan dashboard`
then exits 3, as it does when the baseline comparison is incomplete, and still writes its files.

::: shadowscan.dashboard
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
