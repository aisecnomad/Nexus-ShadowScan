# Changelog

The condensed change log. The full per-change engineering log lives in the
[changelog journal](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-journal.md),
and [RELEASE_NOTES.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
summarizes each release for people who install and operate ShadowScan.

## Unreleased

### Review fixes: connector correctness, CI check names, benchmark framing (October 17)

- `gateway.otel` no longer loses resource attributes from nested OTLP
  exports: `service.name` reaches the finding again, so distinct callers no
  longer merge into one `unknown-service` finding. Regression-tested.
- `endpoint.ebpf` reads the native Tetragon, Falco, Tracee and Hubble export
  shapes it always claimed (snake_case and lowerCamelCase), keeps the flat
  record shape, and reports one warning that marks the scan incomplete when
  records match no known shape, so an unread export cannot look like a clean
  scan. Fixtures cover all four producers, and the Falco example rule also
  emits `fd.sip.name` so AI host names reach the alert.
- `endpoint.host` reports a host inventory row only when its name or path
  matches an AI product signature or its `type`/`category` names an AI
  category; filtered rows add one informational note instead of becoming
  0.7-confidence findings.
- The CI coverage leg is selected by a job-level environment expression
  instead of a matrix `include` key, so its check reports as `test (3.11)` —
  the name the branch rulesets require — rather than `test (3.11, true)`,
  and the required status can actually gate merges. The repository-policy
  test pins the new mechanism.
- The README carries its benchmark fine print in the results themselves: the
  discovery row names the pre-tuning F1 beside the post-tuning, in-sample
  figure, and the weakest per-surface precisions (identity and SaaS in the
  2026-10-11 cases run) are stated next to the headline numbers.
- Documentation restructuring: `docs/production.md` is the rollout guide
  again, with the per-change migration notes in
  `docs/production-migrations.md` and the dated candidate log in
  `docs/history/production-change-history.md`; this changelog is condensed,
  with the full journal relocated to `docs/history/changelog-journal.md`.
- Docs publication: after GitHub Pages is configured for Actions, the
  repository variable `DOCS_PUBLISH` set to `true` republishes the site on
  every docs push to `main`, so publication no longer needs a manual
  dispatch per update; the one-off `publish=true` dispatch still works and
  the policy test pins both explicit paths.
- Offline cloud input is stated loudly: the cloud connector guide and the
  unsupported-`_kind` warning both say that `cloud.aws`, `cloud.gcp`,
  `cloud.azure` and `cloud.oci` replay `--dump-records` exports, not a
  provider's native log, so a CloudTrail file explains itself instead of
  producing an incomplete scan with a cryptic warning.
- Python 3.14 is supported: `requires-python` allows it, CI tests it on
  Linux and macOS, and the hash locks already resolve on it. A PEP 263
  cookie that Python 3.14's own `detect_encoding` refuses (`punycode`,
  UTF-32) stays a coverage gap when it names a slow codec or one that does
  not read ASCII as ASCII — the scanned estate's interpreter may still
  honor it — instead of falling into the keep-default branch and being
  silently analyzed; a bare `utf-16`/`utf-32` cookie is now a gap on every
  interpreter for the same reason. Regression tests force the refusal path
  so the pre-3.14 CI legs exercise it too.

### October 1 – 16 (condensed; the journal has every change)

- README rebuilt as a landing page whose hero banner, architecture diagram
  and cross-tool benchmark chart are generated from the tree and the
  committed benchmark runs, with generation checked in CI.
- Plugin isolation: plugins default to spawned process workers that can be
  stopped at their deadline and never see the raw operator identity key.
- Supply-chain and transport hardening: runtime dependency ranges capped at
  the next major, bounded DNS resolution with a typed HTTP session seam,
  per-connector private-origin grants, and a reviewed Bridge CLI pin for the
  Black Duck job.
- Review-driven hardening across redaction, SSRF controls, parser cost
  budgets, output paths, SARIF rendering and diagnostics, in several dated
  rounds.
- Collection completeness and registry assurance: attested collection scope
  for live AWS, Azure, GCP and Entra scans, vendor and trusted registry
  records, MCP registry provenance, Google and AWS agent registries,
  Microsoft Agent 365 and Entra Agent ID, autonomy tiers with Capability
  Card schema version 2, and the opt-in A2A Agent Card probe with card
  signatures.
- Fleet operations: dashboard, inventory export, control evidence and
  declared governance facts, drift classes with baseline pinning, and threat
  and control references.
- ShadowBench, the nine-surface discovery benchmark, with its estate and
  cases tracks, followed by review fixes. ShadowScan's detection rules were
  changed with the 2026-10-11 estate run's errors in view, so a later
  ShadowScan run on that estate is in-sample. Among those rules, Wudpecker
  and Tactiq are recognised as meeting note-takers by name and domain
  (benchmark-derived: Wudpecker is the ShadowBench estate positive the
  2026-10-11 run missed, and Tactiq was added with it).
- Detection precision and robustness: bounded evidence analysis across
  connectors, ambiguous app-name handling and scoped correlation,
  change-scoped scans (`--diff-base`), an input-defect taxonomy for
  `code.filesystem`, new ecosystems and CycloneDX output, and the October 8
  real-world and discovery benchmark follow-ups.
- Repository rename to `aisecnomad/Nexus-ShadowScan`, the `NexusShadowScan`
  source distribution, and the generated README detection matrix.

## 0.1.2 — 2026-10-08

### Release tag lookup correction

- Fix the production publication gate to query GitHub with the fully qualified
  `refs/tags/v<version>` ref. The previous `tags/v<version>` lookup returned
  HTTP 422 for the existing annotated tag during release preflight. The gate still
  requires the resolved commit to equal the reviewed workflow commit.
- Execute the gate in regression tests against the accepted API ref format,
  including rejection of the old lookup and of missing or mismatched tags.
- Prepare a new version because `v0.1.1` is already immutable. Its TestPyPI
  upload and fresh installation passed; production preflight stopped before
  any PyPI dispatch or upload. Preserve the tag and the rehearsal evidence.

## 0.1.1 — 2026-10-08

The first published version; its TestPyPI upload and fresh installation
passed. Condensed — the
[journal](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-journal.md)
records every change and
[RELEASE_NOTES.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
has the operator-facing summary and upgrade notes.

- Finding identity schema v2: stable, keyed finding ids; comparison
  baselines from earlier runs must be rebuilt.
- Fail-closed scan semantics: limits, malformed or ambiguous exports and
  denied APIs mark the scan incomplete (exit 3) rather than shrinking the
  report; exit codes are documented and tested.
- Evidence and confidence corrections: test and fixture evidence no longer
  establishes an agent, and correlated evidence counts once.
- Connector and signature growth across the nine surfaces, including the
  endpoint inventory connector.
- SARIF severity mapping that GitHub code scanning accepts, with heuristic
  discovery levels kept apart from CVSS-like security severity.
- Release policy: unsigned annotated tags on the exact reviewed commit are
  permitted; publishing goes through the protected workflow and PyPI trusted
  publisher with provenance and SBOM.

## Earlier hardening notes — 2026-09-24

The reconciled pre-release implementation summary lives in the
[journal](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-journal.md).
