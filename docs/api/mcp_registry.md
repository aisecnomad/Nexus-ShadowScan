# MCP registry

The MCP registry module manages **pinned snapshots** of MCP server registries and approved MCP
catalogs. It enriches MCP server findings with provenance information: whether a server is
listed in an approved registry, its publication status and whether a private catalog entry
matches.

## Pinned snapshots

`options.mcp_registries` lists one or more snapshot entries. Each snapshot is a file produced
by `shadowscan mcp-registry snapshot` from a registry that serves the MCP Registry API (the
official `registry.modelcontextprotocol.io` registry or a private one):

```json
{
  "schema": "shadowscan.mcp-registry-snapshot/v1",
  "registry": "https://registry.modelcontextprotocol.io",
  "api": "v0.1",
  "fetched_at": "2026-10-10T00:00:00Z",
  "complete": true,
  "servers": [...]
}
```

Each snapshot is pinned by its SHA-256 digest. ShadowScan verifies the digest on every scan
and rejects a snapshot whose bytes have changed. **Nothing is fetched during a scan** — snapshots
are always read from local files.

## Provenance enrichment

`enrich_mcp_findings()` matches each MCP server finding against the loaded snapshots by server
name and package name. A matched finding receives:

- `metadata.mcp_registry.status` — the server's official status (`approved`, `listed`, …).
- `metadata.mcp_registry.registry` — the registry URL.
- `metadata.mcp_registry.latest` — whether the installed version is the current published version.

A finding whose server appears in an approved registry is treated as having a `registry-record`
tag for governance purposes.

## Approved catalogs

`options.mcp_registries[*].approved_catalog` lists the server IDs or package names an
organisation has vetted independently of the official registry status.

::: shadowscan.mcp_registry
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
