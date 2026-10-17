# Inventory registry

The inventory registry is the set of AI agents an organisation has approved and declared. It
defines the boundary between **shadow** agents (discovered but not registered) and **registered**
agents (known and sanctioned). Reconciliation against the inventory is what makes ShadowScan a
governance tool, not just a discovery scanner.

## Inventory formats

The registry accepts three input formats under the `inventory:` config key:

- **Agent Capability Cards** — YAML files with `metadata.agent_id` and `metadata.owner_team`,
  optionally extended with a `discovery:` block listing the exact resources and name aliases
  the agent is deployed as.
- **`agents.yaml`** — a list-format inventory, one entry per agent, used for bulk import.
- **CSV** — a flat spreadsheet with one column per agent field, for teams that manage inventory
  in a spreadsheet.

## Capability Cards and `schema_version`

A card with `schema_version: 2` may declare:

- `autonomy_profile.level` — the operator's declared autonomy tier (L0–L5).
- `governance:` — EU AI Act risk class, intended purpose, oversight measures, AIUC-1 certificate
  reference and ISO/IEC 42001 scope.

An earlier card's autonomy level is ignored and flagged in the report.

## Reconciliation

`reconcile()` compares every finding against every inventory entry and assigns one of:

| Status | Meaning |
|--------|---------|
| `registered` | Matched to exactly one inventory entry |
| `shadow` | No matching entry found |
| `ambiguous` | Matched multiple entries (conflict) |

A finding is shadow when the scan ran with an inventory and found no match. A scan without an
inventory marks all findings `unassessed` (not shadow).

::: shadowscan.registry
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
