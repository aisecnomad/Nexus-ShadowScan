# Config

The config module parses and validates the scan configuration supplied through a YAML file,
CLI options or the Python API.

## Configuration sources

ShadowScan merges configuration from three sources in order of increasing precedence:

1. **YAML file** — `shadowscan.yaml` (or the file named by `--config`).
2. **CLI flags** — e.g. `--connector`, `--min-confidence`, `--fail-on`.
3. **Environment variables** — each connector reads its own env vars (e.g. `OKTA_API_TOKEN`).

## Key fields

```yaml
inventory:
  - ./inventory/          # Capability Cards, agents.yaml files or CSVs
signatures:
  - ./custom-signatures/  # additional or overriding signature packs
options:
  min_confidence: 0.3     # suppress findings below this confidence (default 0.0)
  fail_on: high           # exit non-zero when a finding reaches this risk level
  timeout: 600            # scan-wide wall-clock deadline in seconds
  dump_records: ./exports # save sanitized connector records (JSONL) for offline re-analysis
  allow_private_origin: false
  llm_triage:
    enabled: false
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
```

## Validation

`ConfigValidationError` is raised for missing required fields, unknown connector names,
conflicting options and any other configuration error that would make a scan unreliable.
The engine raises `SetupError` for problems that are detected after configuration loading
(e.g. a signature directory that does not exist).

## Connector specs

Each entry in `connectors:` is a `ConnectorSpec`: a connector name plus arbitrary key-value
options. Connectors declare their supported keys in `config_keys`; unknown keys produce a
warning. Environment variable references (`${VAR}`) in string values are expanded at load time.

::: shadowscan.config
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
