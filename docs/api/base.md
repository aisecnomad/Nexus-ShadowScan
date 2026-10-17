# Base Connector

`BaseConnector` is the abstract base class every connector inherits from. It defines the two
execution modes, the engine hooks, and thin offline-input and record-validation methods that
delegate to the shared [offline reader](offline.md). `ConnectorContext` is the runtime context
a connector receives: configuration, the signature index, diagnostics and the deadline.

## Execution modes

`run()` picks the mode from the `input:` config key:

- **Live mode**: without `input:`, `run()` checks the packages in `requires` and calls
  `collect()`, which fetches raw records from the provider API.
- **Offline mode**: with `input:`, `run()` calls `load_offline()` on that file or directory
  instead. `collect()` is not called.

`analyze()` turns raw records into `Finding` objects and is the same in both modes. `run()`
sanitizes every finding. A finding that exceeds the sanitizer's safety limit is omitted with
the error `finding omitted: sanitization safety limit exceeded`. A `ConnectorError` marks the
connector skipped, and any other exception is recorded as an error that names its type. Each
of these marks the scan incomplete (exit 3).

## Engine hooks

Class-level attributes and class methods the engine consults instead of special-casing
connector names:

| Hook | Default | Meaning |
|------|---------|---------|
| `cache_roots_separately()` | `False` | An incremental multi-root `paths` scan runs and is cached one job per root |
| `inherits_instance_credentials_approval()` | `True` for the cloud surface or a connector that documents `allow_instance_credentials` | The engine sets `allow_instance_credentials` from the scan options |
| `uses_run_identity_key` | `False` | Jobs share one private per-scan identity key (`ConnectorContext.gateway_identity_key`) |
| `emits_registry_records` | `False` | A built-in connector may keep `metadata["registry_record"]` for its declared `registry_record_types`; the engine drops the key from every other connector's findings |
| `attests_live_scope` | `False` | A built-in live connector records its collection scope; `scope_options` names the non-secret keys the record repeats |
| `estimate_timeout_seconds()` | `None` | Proposes a larger deadline for a large input when the default deadline is in place |
| `scanned_local_paths()` | `[]` | Local trees scanned as the subject of the run, compared with the scan's approval inventories |

## Record validation

`_record_fields_valid()` checks the fields a connector consumes. It returns False for a value
that is not a mapping, a provider error record, a `required` field that is not a nonempty
string, or a `strings`, `mappings` or `arrays` field of the wrong type. It never echoes the
rejected value and reports nothing itself: the connector that calls it reports the skipped
record.

## Offline input

`load_offline()` reads the `input:` path through the shared [offline reader](offline.md). It
discovers files by suffix (`.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`, `.csv`), applies
the `max_input_files`, `max_input_file_bytes` and `max_input_bytes` limits declared in
`shared_config_keys`, unwraps collection envelopes and yields the valid records.

::: shadowscan.connectors.base
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
