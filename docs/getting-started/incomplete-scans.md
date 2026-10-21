# Resolve an incomplete scan

Exit 3 means some selected input could not be analyzed completely. Findings
already collected remain useful, but an empty result does not establish absence.
Keep exit 3 as a failed CI gate.

## Check readiness, then read the scan report

```bash
shadowscan code . --preflight --format json
shadow_reports="$(mktemp -d)"
shadowscan code . --format json --output "$shadow_reports/scan.json"
```

Preflight checks setup and reports `scan_performed: false`. It does not walk
and analyze the full repository, predict content limits or certify completeness.
The second command performs the scan. Its JSON summary includes
`incomplete_reasons`; sanitized connector diagnostics provide the detail.
Terminal warnings intentionally omit source content and credentials.

If writing the report fails, select an existing, writable directory with space
available. That is an output failure, separate from the scan's coverage gaps.
Reports can contain sensitive evidence even after sanitization; store them privately.

## Match the reason to the remedy

These are known failure categories, not a measured ranking across repositories.

| Reason | Next step |
|---|---|
| `oversize-file` | Review the affected files. Exclude generated or out-of-scope data with a specific `--exclude` pattern, or configure `max_file_size` through the filesystem connector after assessing memory cost. |
| `timeout` | Leave the connector timeout unset to allow automatic scaling, or set a deliberate larger `--connector-timeout-seconds`. Split very large scans into explicit roots. A separate process deadline still applies. |
| `unparsed-input` | Correct malformed source or configuration and use a supported text encoding. Unknown binary content and unparsed notebook cells remain gaps. Exclude a fixture only when it is outside the intended scope. |
| `unresolved-link` / `unscanned-input` | Inspect missing submodules, linked targets or unfetched content. Make the intended input available, scan its target explicitly, or document its exclusion. |
| `analysis-limit` / `sanitization-limit` | Inspect the affected input and the named limit. Reduce or split generated data where appropriate. Sanitization limits must not be bypassed to expose raw evidence. |
| `access-denied` / `upstream-error` | Check the connector's documented scopes, connectivity and rate limits, then rerun. |
| `subset-scan` | Run the full intended scope when a deliberately limited mode cannot answer the question. |

An exclusion changes the scope of the result. A complete scan after excluding
files says nothing about those files. Raising the coverage-gap budget does not
repair unread input; unbounded gaps still fail closed.

## Large trees and the scanner's own checkout

When no timeout is configured, the filesystem connector starts at 120 seconds
and can scale to the existing 1800-second ceiling. Its one-second probe counts
up to 180,000 entries; it does not read file contents. An explicit timeout,
including 120, is kept unchanged. A larger allowance does not guarantee that
every repository finishes.

ShadowScan intentionally includes hostile parser and redaction fixtures.
Use `make self-scan` in its checkout for the documented scope; an unrestricted
scan can correctly remain incomplete. The optional benchmark companion has
its own verification and test workflow.

See [scan semantics](../scanning.md), [filesystem configuration](../connectors/code.md)
and [local hooks](../operations/code-precommit.md) for scope and limit details.
