# Reporters

The reporters package turns a `ScanResult` into report text. `RENDERERS` maps each format name
to a renderer: a callable that takes the result as its only positional argument and returns a
string (the `Renderer` protocol). `render(result, fmt, index)` looks the format up, passes the
scan's signature index to CycloneDX so custom-pack signatures are named in the BOM, and raises
`ValueError` for an unknown format. The `table` format is not in `RENDERERS`: the CLI prints it
with `shadowscan.reporters.table.print_table`.

## Formats

`FORMATS` holds the CLI's `--format` choices:

| `--format` value | Output |
|------------------|--------|
| `table` (default) | Rich terminal table, one row per finding, under a header with totals by risk level and surface; with `--output` the file is written as JSON |
| `json` | Full-fidelity JSON report: findings, evidence, risk factors and connector statistics |
| `sarif` | SARIF 2.1.0 for code scanning (GitHub code scanning, Azure DevOps, IDEs); heuristic risk levels go under `shadowscan/heuristic-risk`, never `security-severity` |
| `csv` | One row per finding, with evidence summarised |
| `markdown` | Markdown report for tickets, pull request comments and wiki pages |
| `html` | Self-contained HTML (no external assets) with filtering and evidence drill-down |
| `cyclonedx` | CycloneDX 1.6 JSON: the scan as an AI bill of materials |
| `ocsf` | One OCSF 1.1.0 Detection Finding event (`class_uid` 2004) per finding, in a document whose `scan.status` says whether the scan was complete |

`RENDERERS` also accepts `md` for Markdown, but `md` is not a `--format` choice.

## Sanitization

Every renderer, and `print_table`, sanitizes each finding and sanitizes the connector statistics
in one pass before it writes anything. If that raises `SanitizationLimitError`, a `ValueError`,
the error propagates and no partial report is returned; the CLI then stops with
`could not render report; result data is invalid` and exits 1. Reporters have no placeholder
rows: a finding the engine could not sanitize never reaches them, because the engine omits it
and marks the scan incomplete (exit 3; see [Redaction](redaction.md#safety-limits)).

## Extending

`FORMATS` is computed from `RENDERERS` when the package is imported, and the CLI's `--format`
choices are fixed from it. A renderer added to `RENDERERS` later can be called through
`render()`, but it is not a `--format` value.

::: shadowscan.reporters
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
