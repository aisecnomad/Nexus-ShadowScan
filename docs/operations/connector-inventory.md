# Connector maintenance inventory

The built-in registry in `shadowscan/connectors/__init__.py` is the source of
connector names. Generate a current maintenance snapshot from a reviewed checkout:

```bash
python -m tools.connector_inventory --check --output connector-inventory.json
```

The command counts registered built-ins by surface, records their declared
optional Python modules, accepted configuration keys and offline formats,
and includes dependency declarations and the runtime lock's SHA-256.
Permission guidance comes directly from the existing
[least-privilege table](../connectors.md#least-privilege). Each connector links
to its entry and records the entry's digest and verbatim paragraphs discussing
incomplete or refused collection. Shared collection limits are included too.
These excerpts help find changes; the full connector guide remains authoritative.
An empty excerpt list does not mean that a connector cannot fail.

The check rejects missing connector entries and a stale generated
[configuration reference](../connectors/reference.md). Ordinary tests also
check coverage of every registered built-in. New connectors therefore need
their documentation and declared metadata before this check passes.
No count is hardcoded, and installed third-party plugins are excluded.

The **Connector maintenance inventory** workflow runs weekly and on manual
dispatch from `main`, retaining the JSON and exact source SHA for 90 days.
Compare snapshots to identify additions, dependency changes and documentation
changes for human review. Its token has only `contents: read`; it opens no
issues, commits no files and creates no pull requests. There is no separate
editable inventory for a bot to keep synchronized.

This is static maintenance evidence. It does not contact vendors, instantiate
connectors, read operator credentials, detect upstream API changes, certify
permissions in a tenant, or establish production acceptance. Review upstream
changes and use the [field-evaluation procedure](../evaluation.md) separately.
