# Reporters

Reporters turn a `ScanResult` into one of ShadowScan's eight output formats. They are pure
functions: `render_*(result: ScanResult) -> str`. The CLI selects a renderer via `--format`;
the Python API calls one directly.

## Available formats

| `--format` value | Description |
|------------------|-------------|
| `table` (default) | Coloured terminal table grouped by surface and risk level |
| `json` | Full machine-readable report; the canonical interchange format |
| `sarif` | SARIF 2.1.0 — integrates with GitHub Advanced Security, VS Code, Azure DevOps |
| `csv` | Flat CSV — one row per finding, suitable for spreadsheet analysis |
| `markdown` / `md` | GitHub-flavoured Markdown — for issue bodies and wiki pages |
| `html` | Self-contained HTML report with collapsible sections |
| `cyclonedx` | CycloneDX 1.6 BOM — for SBOM toolchains |
| `ocsf` | OCSF 1.3 (schema 2007 Vulnerability Finding) — for SIEM and data-lake pipelines |

## Redaction

Every reporter calls `sanitize()` on each finding before rendering. Findings whose sanitization
raises `SanitizationLimitError` are excluded from the output (replaced by a placeholder row
in table and Markdown formats) and recorded as a warning. This ensures that credentials and
other sensitive values captured during scanning never appear in the report regardless of the
output format.

## Extending

Register a custom renderer by adding an entry to `RENDERERS` before calling the CLI, or by
implementing a reporter that accepts a `ScanResult` and returns a string.

::: shadowscan.reporters
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
