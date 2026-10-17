# MCP registry

The MCP registry module loads pinned snapshots of MCP Registry listings and matches the MCP
servers that findings report against them: which registry lists each server, whether its pinned
version is listed and is the latest, and whether the registry marks it deprecated or deleted. A
snapshot marked `approved` is the organisation's approved MCP catalog.

## Pinned snapshots

`shadowscan mcp-registry snapshot` lists every server version, deleted ones included, of a
registry that serves the MCP Registry API v0.1: `https://registry.modelcontextprotocol.io` by
default, or another registry named with `--url`. It writes a
`shadowscan.mcp-registry-snapshot/v1` file and prints the SHA-256 to pin. The listing is complete
or nothing is written: a failed request, an invalid page, a repeated cursor or a page or size
limit exits 3.

`options.mcp_registries` pins up to 16 snapshots. Each entry has an `id`, the `snapshot` path,
its `sha256` and the optional boolean `approved`; any other key is rejected:

```yaml
options:
  mcp_registries:
    - id: official
      snapshot: ./mcp-registry.json
      sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    - id: corp-catalog
      snapshot: ./corp-mcp-catalog.json
      sha256: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
      approved: true
```

Nothing is fetched during a scan. Every scan reads each snapshot again without following
symbolic links, checks the pinned digest and validates the document. A snapshot that is missing,
changed, too large, malformed or not `complete` is not used, and the scan is incomplete
(`engine.mcp-registry`, exit 3).

## Matching

`enrich_mcp_findings()` matches every server of an `mcp-server` finding by what its client
fetches or connects to: the package a command launches (registry type and normalized
identifier), the normalized URL of a remote server, or every package and remote a `server.json`
manifest declares. Names a client configuration gives its servers are never looked up, and a
server without such an identity is unidentified. Each server that is identified, or named by its
manifest, gets a `registry` list with one entry per registry that lists it, including the
registry's `status` (`active`, `deprecated` or `deleted`) and `is_latest`. The finding gets
`metadata.mcp_registry` (`registries`, `approved_checked`, `not_in_approved`, `unidentified`) and
review tags from `REGISTRY_TAGS`, such as `mcp-registry-published`, `mcp-unpublished` and
`mcp-registry-unidentified`, each with zero-weight evidence. Disabled servers get `registry`
entries but no tags and no count. A finding whose servers cannot be matched is left without registry data,
and the scan is incomplete (exit 3).

## Approved catalogs

An approved catalog is not an inventory source: it never approves a finding or changes `shadow`
or `registry_match`. When at least one is configured and every approved snapshot loaded,
`not_in_approved` counts the enabled servers that no approved registry lists by their identity,
or lists only as deleted, unidentified servers included, and scoring adds the governance factor
`mcp-not-in-approved-registry`. [MCP registry provenance](../connectors/code.md#mcp-registry-provenance)
describes the matching rules and tags in full.

::: shadowscan.mcp_registry
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
