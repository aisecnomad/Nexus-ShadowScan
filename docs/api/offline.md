# Offline input

The offline module implements the shared machinery for reading exported API records from
files. A connector runs in offline mode when its configuration sets `input:` to a file or
directory path. `BaseConnector` keeps thin methods (`load_offline`, `_unwrap`,
`_read_offline_bytes` and others) that delegate here and that connectors may override.

## Supported formats

| Suffix | Format |
|--------|--------|
| `.json` | One JSON document: a record, an array of records or a collection envelope. A file that is not one document is read as one JSON object per line |
| `.jsonl` / `.ndjson` | One JSON value per line; blank lines are skipped |
| `.yaml` / `.yml` | One YAML document, parsed with a bounded safe loader |
| `.csv` | A header row of unique, nonempty column names, then one record per row |

## Security limits

All reads are bounded:

- **Per-file byte limit**: `max_input_file_bytes`, default 32 MiB, hard ceiling 64 MiB.
- **Aggregate byte limit**: `max_input_bytes` across all files of one input, default 256 MiB,
  hard ceiling 512 MiB.
- **File count**: `max_input_files`, default 10,000, and at most 200,000 directory entries.
- **Per-line byte limit**: 4 MiB for JSONL and CSV, which are read line by line.

A JSON or YAML file is read whole and skipped whole when it does not fit. A JSONL or CSV file
larger than the per-file limit is skipped. Otherwise the aggregate and line limits end it
where they are reached, and the records before that point are kept. Reaching any limit marks
the scan incomplete (exit 3). So do malformed records, provider error responses, a file that
is not valid UTF-8 and a file that changes while it is read; valid records next to a rejected
one are kept. See [offline input limits](../scanning.md#offline-input-limits).

## Collection envelopes

`unwrap()` accepts a record, an array of records, or an envelope with exactly one known
collection key (`records`, `items`, `value`, `data`, `results` and others). An envelope with
several collection keys, a collection that is not an array, or anything other than an object
or an array of objects is rejected. Each record must be a nonempty object with string keys.
An envelope that carries a continuation marker (`has_more: true`, `nextLink`, `nextPageToken`
and similar) is reported as an uncollected next page, which marks the scan incomplete; its
records are still kept.

## Link traversal

`offline_files()` never follows symbolic links. An `input:` path that is, or sits under, a
symlink is an error. Inside a directory, symlinks and special files are skipped, and so are
files without a supported suffix. Each skip is reported and marks the scan incomplete.

::: shadowscan.connectors.offline
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
