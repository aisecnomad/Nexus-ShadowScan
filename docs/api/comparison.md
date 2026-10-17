# Comparison

The comparison module backs `shadowscan diff`: it compares a current JSON report with a baseline
and lists new, resolved, unknown and changed findings. It is deliberately **conservative**: a
finding missing from the current report counts as resolved only when the two scans are
comparable. Otherwise it is listed as `unknown`, the comparison is incomplete and `shadowscan diff`
exits 3. A malformed report raises `ValueError` (exit 1) rather than reading as unchanged.

## Collection-scope provenance

`build_collection_scope()` describes a scan's inputs as a `shadowscan.collection-scope/v1`
fingerprint over the selected built-in connectors with their configuration and resolved paths, the
minimum confidence, the signature index, the scanner source and version, an HMAC derived from
`SHADOWSCAN_IDENTITY_KEY` when it is set, and any `options.mcp_registries`. Scope hashes identify
inputs, not their contents: a file changing is what comparisons measure. A third-party connector,
a live connector that could not attest its scope, a configuration that holds credentials or
sensitive keys, a `code.filesystem` scan with `diff_base`, or `gateway.logs` without
`SHADOWSCAN_IDENTITY_KEY` gets no fingerprint.

`compare_reports()` treats two reports as comparable only when both are complete, their summary
counts match their `findings`, both carry the current finding identity schema, the same connectors
completed and the fingerprints are equal. Unmatched findings with scan-local IDs
(`metadata.identity_scope` other than `keyed`) are listed under `not_comparable`, and they too make
the comparison incomplete.

## Drift classes

Each substantive change is labelled with a class from `DRIFT_CLASSES` and whether it is
**adverse** (it widens what the finding can do, or weakens how it is governed):

| Class | Covers |
|-------|--------|
| `inventory` | New and resolved findings; `kind` and `resource_type` |
| `capability` | `permissions`, `capabilities`, `frameworks`, `model_providers`, `models`, tags other than `autonomy-understated`, `metadata.tool_definition_sha256` |
| `autonomy` | The floor, ceiling, oversight and initiation of `metadata.autonomy` |
| `governance` | `owner`, `shadow`, `registry_match`, `metadata.registry_reconciliation.status`, the `autonomy-understated` tag |
| `coverage` | The reasons the comparison is incomplete; any reason is adverse |

Risk score, level and factor changes appear in `changed_fields` but are not classified.
[Scheduled drift detection](../operations/drift.md#drift-classes) lists when each class is adverse.

## Baseline pinning

`load_report_with_digest()` returns the SHA-256 of a report file's raw bytes and, given
`expected_sha256`, raises `ReportDigestMismatch` before parsing (`--baseline-sha256`, exit 1).
`baseline_lifecycle_reasons()` makes the comparison incomplete when the baseline started more than
`max_baseline_age_days` ago (`--max-baseline-age-days`, 1 to 36,500), has no valid timezone-aware
`started_at`, claims a start in the future, or started after the current scan.

::: shadowscan.comparison
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
