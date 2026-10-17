# Base Connector

`BaseConnector` is the abstract base class every connector inherits from. It defines the
two-phase execution model, the offline input machinery, engine hooks, and the record-validation
helpers connectors use to guard against malformed API responses.

## Execution phases

Every connector supports two modes selected by the presence of the `input:` config key:

- **Live mode** — `collect()` calls the provider API and yields raw records. The engine calls
  this in a background thread during the scan.
- **Offline mode** — `collect()` reads an export file or directory instead of calling the API.
  This enables reproducible analysis and testing without credentials.

`analyze()` turns raw records into `Finding` objects and is the same in both modes.

## Engine hooks

Connectors declare capabilities the engine consults at scan time through class-level attributes:

| Attribute | Default | Meaning |
|-----------|---------|---------|
| `incremental_by_root` | `False` | Enable per-root incremental caching for static inputs |
| `needs_instance_credentials` | `False` | Requires cloud instance credentials (opt-in to `allow_private_origin`) |
| `emits_registry_records` | `False` | Yields vendor agent registry records (triggers reconciliation) |
| `live_scope_attestation` | `None` | Whether live collection covers the full scope of the provider |

## Record validation

`_record_fields_valid()` validates that a raw API record has the expected field types. Connectors
call this to guard against malformed records; an invalid record increments the warning count and
marks the scan incomplete rather than raising an exception that would stop the connector.

## Offline input

`load_offline()` reads the `input:` path (a file or directory) using the shared
[offline reader](offline.md). It discovers files by extension (`.json`, `.jsonl`, `.yaml`,
`.csv`), applies byte limits, unwraps collection envelopes and yields parsed records.

::: shadowscan.connectors.base
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
