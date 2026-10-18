# Vendor registries

The registries module covers vendor registries of AI agents, such as an AWS Agent Registry,
Microsoft Agent 365 or a Google Agent Registry. A connector that reads one emits one finding
per registry record, carrying `metadata["registry_record"]` in the
`shadowscan.registry-record/v1` contract that the module docstring below shows. A record is a
declaration that someone registered an agent, not proof that it runs: its evidence has weight
0.5 and its own confidence group.

Only a built-in connector that declares the `emits_registry_records` engine hook may carry the
key, and only for the registry types it lists in `registry_record_types`; the engine removes it
from every other connector's findings, a plugin's included. A record that breaks the contract is
malformed: it takes no part in reconciliation or approval, and the scan records it under
`engine.registries` and is incomplete (exit 3).

## Record statuses

Connectors map vendor statuses onto `approved`, `registered`, `pending`, `draft`, `rejected`,
`deprecated`, `blocked` and `unknown`. Only `approved`, `registered` and `pending` records
register what they bind.

## Reconciliation

`reconcile_registries()` compares records with the observed findings (those without a record).
A binding matches only by exact resource and, where the binding sets them, equal provider,
account and region; names never match. It writes `metadata["registry_reconciliation"]` with
the status `registered-and-observed`, `registered-not-observed`, `observed-not-registered` or
`not-comparable`. These statuses are informational: they do not change `shadow`, approval or
risk.

## Trusted approvals

Records approve findings only for the registry instances listed in
`options.trusted_registries`, each by registry type and exact id; a whole registry type cannot
be trusted, and `entra-agent-registry` cannot be trusted at all. `TrustedApprovals` rebuilds the
approvals from each run's records, so nothing is cached. By default only an `approved` record
with `approval_mode: manual` approves: its own record finding and the exact resources of its
usable bindings. An entry's `allow_auto_approved`, `allow_registered_only` and
`allow_offline_records` also accept approved records whose approval mode is not `manual`,
`registered` records and records replayed from an offline export. These approvals are matched
together with the loaded inventory under the same rules, so a finding that a card and a record
both approve is ambiguous and stays shadow. Records that only those switches would accept, and a
trusted registry that produced no records, are reported in advisory `engine.inventory`
warnings; they approve nothing.

[Vendor registries as inventory sources](../inventory.md#vendor-registries-as-inventory-sources)
covers the record fields, the connectors that emit records and configuration examples.

::: shadowscan.registries
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
