# Incremental cache

With `--incremental` (or `options.incremental: true`), the incremental cache reuses a
completed connector result when the fingerprint of its static inputs is unchanged. It
is conservative: an input it cannot fingerprint, or an entry it cannot read or verify,
means the connector runs in full. The [incremental scans](../scanning.md#incremental-scans)
guide covers the options and limits.

```yaml
options:
  incremental: true
  state_dir: ../private-scan-state
connectors:
  - name: code.filesystem
    paths: [./repo-a, ./repo-b]
```

## Eligible connectors

- `code.filesystem`, except a scan with `diff_base` or `include`. Each root of a
  multi-root `paths` scan is cached separately.
- `code.github`, `code.gitlab`, `cloud.aws`, `cloud.azure`, `cloud.gcp` and `cloud.oci`
  with an offline `input`.

Live APIs are collected on every run, because an unchanged configuration cannot
establish that remote state is unchanged. So is every other connector, and a plugin
that replaces a built-in connector, which may read inputs the cache does not know.
`--dump-records` disables the cache, because a cached result has no records to export.

## Fingerprint and reuse

The fingerprint is a SHA-256 digest over the cache format, the ShadowScan version, a
digest of the scanner's source, the signature index, the connector's name, id and
configuration, the scan-wide coverage gap budget (`max_coverage_gap`), a commitment to
`SHADOWSCAN_IDENTITY_KEY` when it is set, and each input root: the content of every file
below it, apart from directories a code scan excludes by name, plus the mode, times,
device and inode of every file and directory, each file's size and, with `use_git`, each
Git checkout's HEAD and shallow boundary. For `code.github` and `code.gitlab` only the
checkout directories inside the `input` directory count. A code file over
`max_file_size` contributes only its metadata. Hashing is bounded (512 MiB, 200,000
entries and 30 seconds per snapshot, 64 MiB per file); exceeding a bound, or meeting a
symbolic link or special file, falls back to a full run. Because the budget is part of
the fingerprint, a stricter budget never reuses a result that a looser one judged
complete.

The input is fingerprinted again before a cached result is used, and a fresh collection
follows when it changed. After a fresh collection it is fingerprinted once more; a
change, or an input that can no longer be fingerprinted, marks the connector incomplete
with the error "static input changed during the scan; rerun required", so the scan
exits 3.

Findings are stored before reconciliation, scoring and correlation, and those stages
always run again. Only a result without errors that was neither skipped nor incomplete
is stored. Its warnings, coverage ledger (`coverage`) and `declared_omissions` are stored
with it and replayed on every hit, and the connector's statistics report `cached: true` with zero objects examined. A result that
carries credential pseudonyms is stored only when `SHADOWSCAN_IDENTITY_KEY` supplies a
stable key.

## State directory

State lives in `options.state_dir` (`--state-dir`), by default
`$XDG_STATE_HOME/shadowscan`, or `~/.local/state/shadowscan` when `XDG_STATE_HOME` is
unset, empty or relative. It must be a private (0700) directory owned by the scanning
user, reached without symbolic links and outside every scan input; otherwise the cache
is disabled with a warning and every connector runs in full. Entries are 0600 JSON
files written atomically. An entry that another user owns, that group or others can
access, or that exceeds 64 MiB is ignored. Entries unused for 30 days expire, and the
cache keeps at most 256 entries and 512 MiB, removing the least recently used first.

With `SHADOWSCAN_IDENTITY_KEY` set, an entry carries an HMAC-SHA256 that binds its
format, slot, fingerprint and payload; without it, only a SHA-256 checksum of the
payload, which detects corruption but not a writer who controls the scanner account.
An entry that does not verify is a cache miss.

::: shadowscan.incremental
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
