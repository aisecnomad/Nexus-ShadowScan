# Changelog

Notable user-visible changes in each release, newest first, in the style of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md)
holds the detailed entry for every change, and the
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/release-notes.md)
say what to do on upgrade. A change adds its detailed entry to the engineering log and a
bullet under the matching heading of `[Unreleased]` here.

## [Unreleased]

Changes on `main` since 0.1.2. They are not published or tagged; pin a reviewed commit SHA.

### Added

- Commands: `shadowscan endpoint` (workstation AI clients), `merge` (fleet reports), `dashboard` (static fleet page and `shadowscan.inventory/v1` export), `controls` (control evidence report) and `mcp-registry snapshot`.
- `shadowscan diff` drift classes (`inventory`, `capability`, `autonomy`, `governance`, `coverage`) with `--fail-on-drift`, baseline pinning (`--baseline-sha256`, `--max-baseline-age-days`) and `--shadow-only`; weekly drift templates.
- Autonomy tiers (`metadata.autonomy`, L0 to L5) and Capability Card schema version 2 with declared governance facts.
- Edition-qualified threat and control references (`metadata.threats`, `metadata.controls`) for OWASP, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1, replacing `metadata.compliance`.
- Vendor agent registry records (AWS Agent Registry and AgentCore, Google Agent Registry and Gemini Enterprise, Microsoft Agent 365 and Entra Agent ID) with `options.trusted_registries`, and delegated Graph auth in `identity.entra`.
- MCP registry snapshots and approved MCP catalogs (`options.mcp_registries`), and an A2A Agent Card probe (`endpoint.mcp` `agent_card_urls`) with card signature checks.
- Attested collection scope for live `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` scans, so `diff` can resolve findings between two complete live scans.
- Code scans: `--diff-base`, `--triage`, `--format ocsf`, opt-in `agent_granularity: source`, path context, cross-signal corroboration, and new signatures and ecosystems.
- Risk scoring capability interactions (`combination:` factors), tunable under `options.risk_weights.combinations`.
- Advisory AI review gate for pull requests, the ShadowBench nine-surface benchmark, `make self-scan`, a complexity ratchet, coverage-guided fuzzing of the redaction and source-lexing code, and an OpenSSF Best Practices evidence page that claims no badge.
- The next release uploads a source distribution beside the wheel.

### Changed

- The repository is renamed to `aisecnomad/Nexus-ShadowScan` (formerly `aisecnomad/Project-Nexus`); OCSF events name the vendor `Nexus ShadowScan`.
- Coverage gaps the scanner can bound are budgeted (`max_coverage_gap`, 2% of examined entries by default, judged per scan root and repository) and always reported; `strict_coverage` or `--max-coverage-gap 0` is strict accounting. Gaps it cannot bound still exit 3.
- Connector deadlines scale to their input while `connector_timeout_seconds` is unset; a value you set, 120 included, is fixed, and an overrun keeps its findings.
- Rebaseline: default risk weights, low-code autonomy evidence and detection precision change, and finding ids change for live `cloud.aws` AgentCore gateways, Atlassian exports and long Kubernetes names.
- More malformed or over-budget inputs (lockfiles without a manifest, low-code graphs, skill and MCP descriptions, network log records) end a scan incomplete (exit 3).
- The detection rules were changed after the 2026-10-11 ShadowBench estate run with that run's errors in view (Wudpecker and Tactiq are recognised as meeting note-takers by name and domain (benchmark-derived); ambiguous Gemini names, Notion bots, gateway routes, Kubernetes serving images, n8n HTTP model calls and ServiceNow flow names were adjusted), so a later ShadowScan run on that estate is in-sample.
- `shadowscan merge` refuses reports with another identity schema or reused finding ids, and fleet reports move to `shadowscan.fleet-merge/v2` with a three-state shadow status.
- The incremental cache moves to entry format 5 and authenticates keyed entries with an HMAC, so every entry misses once after upgrading.
- Release attestation bundles are named `provenance.sigstore.json` and `sbom.sigstore.json`; SARIF notifications name their connector once; runtime dependency ranges are capped at the next major version.
- The CLI is a package with a typed reporter protocol, and the filesystem and Kubernetes connectors are split into bounded modules (ADR-005).
- The README is a short landing page: the detection matrix, benchmark results, SARIF and finding examples, security controls and redaction rules moved to the documentation site, and `RELEASE_NOTES.md` points to `docs/release-notes.md`.

### Fixed

- Detection precision and completeness corrections from the real-world, Shadow AI discovery and ShadowBench benchmark runs: the JavaScript, Rust, PHP, F# and C# lexers, stray NUL bytes, lockfiles, `go.mod`, app-name attribution, tool dispatch, the `ci` profile and diff-scoped walks. `identity.okta` and `identity.entra` leave out sign-in clients that request only OpenID Connect scopes and carry no AI attribution or signature match.
- OCSF events always carry the required `time` attribute.
- On CPython 3.12.0 to 3.12.3 a file with a very long line no longer stalls redaction; the finding is omitted and the scan is incomplete.
- A report nested past 256 levels is refused as nesting on every interpreter, and a CPython 3.12 tokenizer fault is an unreadable source rather than an exception.
- Two CPython 3.11 serial-run test flakes no longer depend on cyclic-GC timing.

### Security

- Redaction withholds many more credential forms across six rounds of credential fixes: env-file, netrc and settings passwords, fallbacks and defaults, typed reads, block-scalar opaque secrets and AWS CLI positional settings.
- Plugin workers start without credential-shaped environment variables (npm `_auth`, webhook values and .NET connection strings included) and without the raw identity key; a process-mode plugin keeps its supervisor's deadline.
- Per-connector private-origin grants, bounded DNS resolution, a pre-clone DNS check that pins Git to the checked addresses, and an HTTP client that ignores proxy environment variables.
- A triage reply steered by scanned content cannot change a finding's risk, shadow status, kind or tags.
- aiohttp 3.14.4 fixes three advisories (Dependabot #270-#274 carried with regenerated hash locks).

## [0.1.2] - 2026-10-08

### Fixed

- The release workflow's production publication gate queries the fully qualified `refs/tags/v<version>` ref; the previous `tags/v<version>` lookup returned HTTP 422 for the existing annotated tag. Scanner behavior is unchanged from 0.1.1, whose `v0.1.1` tag is immutable.

## [0.1.1] - 2026-10-08

The first alpha candidate of the `NexusShadowScan` distribution. It reached TestPyPI and the `v0.1.1` tag, but not production PyPI.

### Added

- 38 connectors across nine discovery surfaces, including `endpoint.inventory`, `network.logs` and `runtime.processes`, and the offline runtime inventory connectors.
- `--format cyclonedx` (a CycloneDX 1.6 AI bill of materials), MCP configuration and coding-agent posture findings, and opt-in LLM triage.
- The `NexusShadowScan` distribution, published through PyPI trusted publishing with GitHub attestations.

### Changed

- Finding ids follow the v2 identity schema, independent of `kind`; rebuild comparison baselines.
- Limits, malformed exports, denied APIs, timeouts, oversize files and links leaving the scan root make a scan incomplete (exit 3), and exit 1 means no scan result.
- Evidence found only in tests or fixtures no longer establishes an agent unless `--include-tests` is set, and correlated evidence counts once.
- SARIF results are warnings or notes carrying the heuristic risk level, without `security-severity`.
- Gateway callers are agentic only from agent runtime operations, MCP endpoints or agent-loop cadence.

### Security

- Reports are written atomically with owner-only permissions; HTML reports carry a strict Content-Security-Policy, CSV cells are neutralized against formula injection and Markdown is defanged.
- Keyed credential evidence, wider redaction (including keys passed positionally to LLM SDK calls), scanned repositories read without following links, HTTPS, origin and private-address controls on live collection, and third-party plugins only by exact-name allowlist.

## Pre-release hardening - 2026-09-24

The reconciled pre-release implementation, before the first tag.

- Security: sensitive values are redacted before source evidence is emitted, TLS verification rejects every falsy setting, live AWS account attribution is checked through STS, report imports and GitHub and GitLab downloads fail closed, symlinked roots are refused, injected HTTP sessions keep the destination policy with bounded bodies, and configuration rejects missing `${ENV}` values, duplicate YAML keys and unknown options. Finding identity no longer includes `kind`. Full Apache-2.0 `LICENSE` text and `NOTICE`.
- Reliability: pagination, regional and page failures keep valid neighbors and partial observations and mark the scan incomplete; SDK clients use finite timeouts and retries; connector completion order no longer decides merged ownership.
- Operations: a disposable non-root worker image (`Dockerfile`) with an allowlisted build context, CI per Python version, and the `docs/production.md` rollout checklist.
- Migration: finding IDs for promoted resources change, so rebuild comparison baselines and incremental state; install from a reviewed tag or SHA, not `main`.
- Known limits: connector deadlines are cooperative, SDK timeouts are not a whole-scan deadline, and incremental cache locking is POSIX-only, so keep a host process deadline.

[Unreleased]: https://github.com/aisecnomad/Nexus-ShadowScan/compare/v0.1.2...main
[0.1.2]: https://github.com/aisecnomad/Nexus-ShadowScan/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/aisecnomad/Nexus-ShadowScan/tree/v0.1.1
