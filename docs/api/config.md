# Config

The config module parses and validates the scan configuration, whether it comes from a YAML
file (`ScanConfig.from_yaml`), a mapping (`ScanConfig.from_dict`) or a `ScanConfig` built in
Python, which validates itself on construction. The
[configuration guide](../getting-started/configuration.md) shows the common options.

## Configuration sources

- **YAML file**: `shadowscan scan` requires `--config` / `-c`. The file must be UTF-8 text of
  at most 8 MiB, neither a symbolic link nor inside one, and a key repeated in one mapping is
  rejected. Relative paths resolve beside the file.
- **Command line**: a scan option given on the command line replaces the file's value (for
  example `--fail-on`, `--dump-records`, `--connector-timeout-seconds`,
  `--job-deadline-seconds` and the `--allow-…` / `--deny-…` switches). `--inventory`,
  `--signatures` and `--allow-plugin` add to the file's lists, and `--min-confidence` keeps
  the higher of the two thresholds. `--only` runs only the named connectors or labels.
- **Environment**: `${VAR}` references are expanded at load time. `${VAR}` fails when the
  variable is missing or empty; `${VAR:-default}` uses its fallback instead. A connector key
  with an environment-variable fallback uses the configured value and reads the variable only
  when the key is unset or null (`ConnectorContext.get`): `identity.okta` reads `token`, then
  `OKTA_API_TOKEN`.

## Key fields

```yaml
inventory:
  - ./inventory/              # Capability Cards, agents.yaml files or CSVs
signatures:
  - ./custom-signatures/      # extra signature packs
options:
  min_confidence: 0.3         # drop findings below this confidence (default 0.0)
  fail_on: high               # exit 2 when a complete scan has a finding at or above high
  connector_timeout_seconds: 300  # completion deadline per connector (default 120)
  job_deadline_seconds: 3600  # CLI process deadline; exit 3 on expiry (default: none)
  dump_records: ./exports     # save sanitized connector records (JSONL) for offline re-analysis
  allow_private_origin: false
  llm_triage:
    enabled: false
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
```

## Validation

`ConfigValidationError`, a `SetupError` and a `ValueError` whose message never echoes a
configured value, is raised for an unsupported field or connector key, a value of the wrong
type or range, conflicting options (such as both `connector_timeout_seconds` and its
deprecated alias `connector_timeout`) and a `${VAR}` whose variable is missing or empty. The
CLI prints it and exits 1 before anything is scanned. The engine raises `SetupError` for
problems found when it is constructed, such as a signature directory that does not exist.

An unknown connector name is not a configuration error, because parsing cannot tell it from
a third-party plugin: the engine records the failed lookup as an error on that connector, so
the scan is incomplete (exit 3) while the other connectors still run.

## Connector specs

Each entry in `connectors:` becomes a `ConnectorSpec`. An entry is a connector name, or a
mapping with `name`, optional `enabled` and `label`, and the connector's options inline or
under `config:` (one key may not appear in both). A built-in connector accepts only its
`config_keys` (`shadowscan connectors` lists them) and the shared keys `input`, `label`,
`allow_private_origin` and the offline input limits; any other key is rejected, with a
suggestion when it is close to a valid one. Plugin keys are not checked. Keys starting with an
underscore are reserved for the engine and rejected for every connector.

::: shadowscan.config
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
