## Unreleased

- Bump the development virtualenv pin from 21.14.11 to 21.14.13 (GHSA-cx6f-vjhg-g3cc / CVE-2026-115586). The advisory is a local prompt-injection regression in the bash activator when `--prompt` is attacker-controlled and promptvars is off; it does not affect the runtime lock or production workers. The CI lock and constraint file are updated; Scorecard's Vulnerabilities check should clear on the next run.

- The 0.1.4 publication is recorded (tag `v0.1.4` on `94fda063`, the PyPI
  upload and the GitHub release of 2026-10-23).
