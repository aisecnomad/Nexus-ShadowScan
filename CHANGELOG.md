# Changelog

One summary per release. Detailed implementation history is maintained in the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md);
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
explain operator migrations. Earlier per-change entries are preserved in the
[change-history archive](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-detail.md).

## Unreleased

- Bump the development virtualenv pin from 21.14.11 to 21.14.13 (GHSA-cx6f-vjhg-g3cc / CVE-2026-115586). The advisory is a local prompt-injection regression in the bash activator when `--prompt` is attacker-controlled and promptvars is off; it does not affect the runtime lock or production workers. The CI lock and constraint file are updated; Scorecard's Vulnerabilities check should clear on the next run.

- The 0.1.4 publication is recorded (tag `v0.1.4` on `94fda063`, the PyPI
  upload and the GitHub release of 2026-10-23).

- The five precision findings of the #320 head review are carried: the
  `gateway.logs` reason coverage is scoped to its provider-error,
  pagination and envelope-shape diagnostics, the wheel-digest guidance
  names the build-process umask, the deviation record names #318 and #319
  as the merged pull requests, the 0.1.3 redaction gap is scoped to keys
  the redaction does not withhold, and the v0.1.3 deviation note is marked
  as the maintainer's own record.

- The 0.1.4 release's review and its deviations from the publishing runbook
  and `AGENTS.md` are recorded; the 0.1.4 release notes, changelog summary
  and rollout guide are corrected against 0.1.3, and the publishing
  runbook's step 6 names the production run's artifact and rebuilds the
  wheel from an archive of the tag under `umask 022`, with the tag's own
  build-backend lock.

## 0.1.4 — 2026-10-23

- The 0.1.3 publication is recorded (tag `v0.1.3` on `aee3c984`, the PyPI
  upload and the GitHub release of 2026-10-22), the publishing runbook
  explains PyPI's change-of-provenance warning on 0.1.3 and how a later
  rename avoids one, and a test tolerates a child process that exits between
  its liveness check and the cleanup kill.

- Offline inputs are counted under explicit incomplete reasons: the shared
  offline readers, directory walk and export loader, the export writer and
  the inventory card reader all report coverage gaps instead of silently
  truncating or failing open.

- The 0.1.3 release notes and changelog are corrected against the actual
  publication, and the publishing runbook's step 6 names the production run's
  artifact and rebuilds the wheel from an archive of the tag under `umask 022`,
  with the tag's own build-backend lock.
