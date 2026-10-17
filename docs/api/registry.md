# Inventory registry

The registry module loads the sanctioned agent inventory and matches findings against it. A
finding that exactly one inventory entry approves is registered (`shadow: false`, with
`registry_match` set to the entry's agent id); one that no entry approves is **shadow**
(`shadow: true`). Approved records of the vendor registries listed in
`options.trusted_registries` also count as inventory (see [vendor registries](registries.md)).
Without inventory files or trusted registries nothing is assessed: `shadow` and
`registry_match` stay null.

## Inventory formats

Inventory paths come from `inventory:` in the configuration or the repeatable `--inventory`
option. Directories are searched recursively for `.yaml`, `.yml`, `.json` and `.csv` files, and
symbolic links are never followed. Each file holds one of:

- **Agent Capability Cards**: a document with a `metadata` mapping that names the agent
  (`agent_id`, `id` or `name`) and optionally its owner (`owner_team`, `owner` or
  `owner_email`), and a `discovery:` block with the resource patterns the agent is deployed
  as, name aliases and optional scope constraints.
- **Simple list**: `agents: [{id, name, owner, resources, names, autonomy_level, ...}]` in YAML
  or JSON, or a bare list of the same entries.
- **CSV**: a header with `agent_id`, `id` or `name` and optional columns such as `owner`,
  `resources` and `autonomy_level`; list cells separate their items with `|`.

A missing path, a glob that matches no file, a malformed entry, an unknown field or a duplicate
key fails loading, and no scan runs; the message names the path and the location in the file,
never a value. An empty inventory is written as `agents: []`.

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
several entries approve is ambiguous and stays shadow, with
`registry_match_reason: ambiguous-resource-approval`. A missing or redacted resource or scope
cannot be approved by any pattern, and a gateway caller whose identity is only operator-asserted
or unverified becomes a review candidate tagged `registry-identity-unverified`. The
[inventory guide](../inventory.md#matching-and-approval) describes each rule.

::: shadowscan.registry
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
