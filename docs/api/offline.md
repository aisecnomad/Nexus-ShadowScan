# Offline input

The offline module implements the shared machinery for reading exported API records from files.
Every connector can run in offline mode by setting `input:` to a file or directory path; this
module handles all the reading, parsing, validation and limit enforcement.

## Supported formats

| Extension | Format |
|-----------|--------|
| `.json` | Single JSON value or JSON array |
| `.jsonl` | Newline-delimited JSON (one record per line) |
| `.yaml` / `.yml` | YAML document or list |
| `.csv` | Comma-separated values (header row required) |

## Security limits

All reads are bounded to prevent memory exhaustion from large exports:

- **Per-file byte limit** — a single export file is read up to a configurable maximum.
- **Aggregate byte limit** — the total bytes read across all files in a directory is bounded.
- **Per-line byte limit** — JSONL reading rejects individual lines that exceed the line limit.

Exceeding any limit marks the scan incomplete and records a warning; records read before the
limit was hit are still returned.

## Collection envelopes

Provider API exports often wrap their records in a collection envelope (`{"value": [...]}`,
`{"items": [...]}`, etc.). `unwrap()` unwraps the known envelope shapes; unrecognised shapes
are passed through as-is. A partial export that carries a pagination cursor is flagged as
incomplete.

## Link traversal

`offline_files()` discovers files in a directory but **never follows symlinks** to prevent
path-traversal attacks on untrusted export archives. Only regular files with a recognised
extension are returned.

::: shadowscan.connectors.offline
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
