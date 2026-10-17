# Incremental cache

The incremental cache avoids re-running connectors whose inputs have not changed since the last
scan. It is a **conservative, content-addressed** cache: a connector's results are reused only
when ShadowScan can prove — by checking the content hash of its inputs — that the same analysis
would produce the same findings.

## What can be cached

Only **static-input connectors** are eligible for caching:

- Local code checkouts (`code.filesystem`, `code.github` with `--offline`)
- Exported cloud or API inventories (any connector with `input:` pointing to a local file)
- Connectors that declare `incremental_by_root: True`

**Live API connectors are never cached.** The API's remote inventory may have changed even if
the connector configuration has not.

## Cache semantics

- Findings are stored **before** reconciliation, scoring and correlation. Those stages always
  run again on the cached results so that a registry change, policy update or new baseline
  affects the current report without requiring a re-scan.
- The cache key combines the connector name, its configuration hash and the SHA-256 of each
  input file.
- Cache state is local to the scanning user's account and must be stored **outside all scan
  inputs** to prevent an attacker from planting a stale cache entry alongside a malicious
  checkout.

## Security properties

- Cache entries are stored with restricted permissions (`0o600`).
- An entry whose HMAC does not verify is rejected and the connector runs again.
- A cache hit never suppresses a warning about the connector: coverage flags from the cached
  run are replayed in the current `ScanStats`.

::: shadowscan.incremental
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
