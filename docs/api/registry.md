# Inventory registry

The registry module loads the sanctioned agent inventory and matches findings against it. A
finding that exactly one inventory entry approves is registered (`shadow: false`, with
`registry_match` set to the entry's agent id); one that no entry approves is **shadow**
(`shadow: true`). Approved records of the vendor registries listed in
`options.trusted_registries` also count as inventory (see [vendor registries](registries.md)).
When no inventory path is given and no trusted registry is configured, nothing is assessed:
`shadow` and `registry_match` stay null. An inventory path that loads no entries, such as an
empty directory or `agents: []`, still counts: every finding is then shadow unless a trusted
registry approves it.

## Inventory formats

Inventory paths come from `inventory:` in the configuration and the repeatable `--inventory`
option, which adds to them. Directories are searched recursively for `.yaml`, `.yml`, `.json`
and `.csv` files, and symbolic links are never followed. A YAML file may hold several
documents and a JSON file holds one; each document is an entry, a list of entries or an
`agents:` mapping that holds the list. An entry with a `metadata` mapping is a card, any other
a simple entry:

- **Agent Capability Card**: a `metadata` mapping that names the agent (`agent_id`, `id` or
  `name`) and optionally its owner (`owner_team`, `owner` or `owner_email`), and an optional
  `discovery:` block with the resource patterns that approve findings, name aliases and scope
  constraints.
- **Simple entry**: a mapping such as `{id, name, owner, resources, names, autonomy_level}`.
- **CSV**: one simple entry per row, under a header with `agent_id`, `id` or `name` and optional
  columns such as `owner`, `resources` and `autonomy_level`; list cells separate their items
  with `|`.

A missing path, a glob that matches no file, a malformed entry, an unknown field or a duplicate
key fails loading, and no scan runs; the message names the path and, for a malformed file, the
location in it, never a value.

## Card schema version

`schema_version` is 1 when omitted, and only 1 and 2 are valid. A version 2 card may declare
`autonomy_profile.level` (0 to 5 on the L0-L5 scale) and a
[`governance:` block](governance.md). A version 1 card's `autonomy_profile.level` is ignored
and reported as an advisory `engine.inventory` warning.

## Matching

`Inventory.match` approves a finding only through an explicit, case-sensitive `resources` glob
that matches `finding.resource`, and only when every scope constraint the entry sets
(`surfaces`, `providers`, `accounts`, `regions`, `discriminators`) matches too. Names and
aliases never approve: they only add `metadata.registry_suggestions` for review. A finding that
several entries approve is ambiguous and stays shadow, with `metadata.registry_match_reason`
set to `ambiguous-resource-approval`. A missing or redacted resource or scope
cannot be approved by any pattern, and a gateway caller whose identity is only operator-asserted
or unverified becomes a review candidate tagged `registry-identity-unverified`. The
[inventory guide](../inventory.md#matching-and-approval) describes each rule.

::: shadowscan.registry
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
