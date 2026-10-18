# Changelog

One line per change, newest first, with the detailed entry for each in the
engineering log (`docs/engineering-log.md`, which this file was until October
2026). `RELEASE_NOTES.md` says what changes on upgrade for people who install
and operate ShadowScan.

## Unreleased

Changes on `main` since 0.1.2, in the order the engineering log records them
(newest first). They are not published or tagged; pin a reviewed commit SHA.

The detection rules were changed after the 2026-10-11 ShadowBench estate run
with that run's errors in view (Wudpecker and Tactiq are recognised as meeting
note-takers by name and domain (benchmark-derived); ambiguous Gemini names,
Notion bots, gateway routes, Kubernetes serving images, n8n HTTP model calls
and ServiceNow flow names were adjusted), so a later ShadowScan run on that
estate is in-sample.

- SARIF notifications name their connector once; the docs show how one scan gives both the JSON ledger and SARIF (October 18)
- The credential oracle's slow rows run with a budget that coverage tracing cannot exhaust (October 18)
- Filesystem connector split into walk, file-scan and findings collaborators (ADR-005 steps 2-5; #259; October 18)
- A diff-scoped walk reports the connector deadline's remainder against the diff-selected files only; the walk's budget reservation drops an unreachable model-artifact branch (October 18)
- The untraced CI test legs run on pytest-xdist workers; the coverage-traced leg stays serial, as its time budgets were measured (#259; October 17-18)
- OpenSSF Best Practices evidence page, claiming no badge (#259; October 17)
- Release attestation bundles are named `provenance.sigstore.json` and `sbom.sigstore.json` (#259; October 17)
- Self-scan of the checkout in `make check` and CI, with every exclusion explained (#259; October 17)
- Complexity ratchet holds function and module size and fails closed (#259; October 17)
- Coverage-guided fuzzing of the redaction and source-lexing code (#259; October 17)
- KubernetesConnector.analyze decomposed into per-concern helpers (#259; October 17)
- A file's source-binding time budget is counted as `timeout`, as the docs define it (October 18)
- Under the ci profile a project whose manifest repeats a key is a project, as npm and Composer read it; a template at the repository root is documented as not declared (October 18)
- Plugin workers also start without npm's per-registry `_auth`, more webhook names and values, and .NET connection strings under any configuration path (October 18)
- A process-mode plugin's credential identities are labelled `keyed` under the operator's identity key again (October 18)
- A report nested past 256 levels is refused as nesting on every interpreter, not only where the parser runs out of stack (October 18)
- A CPython 3.12 tokenizer fault is an unreadable source, not an exception; JavaScript string spans stay inside the text (#259; October 18)
- go.mod require blocks read in linear time; no dependency named "(" (October 18)
- CLI package, reporter protocol, condensed README, identity sign-in clients and API page narratives (#252, #253; October 17)
- Credential review fixes: env-file passwords, typed reads, pasted names, repeated credentials, labels and cut-read evidence (October 17)
- Coverage gaps take one decision, judged per root and repository (October 17)
- Review fixes: what diff holds back under the ci profile (October 17)
- Engine review fixes: surrendered findings, explicit deadlines, the cache key and split jobs (October 17)
- Review fixes: connector correctness, CI check names, benchmark framing (October 17)
- Review fixes: credential precision, the ci profile, incomplete reasons, the ownership move and plugin environments (October 17)
- Credential quota disclosed, Bedrock owner tags collected, repeated tags count once (October 17)
- Precision, completeness and connector requirements from an outside review (October 17)
- Coverage gaps are budgeted, so exit 3 means something again (October 17)
- Connector deadlines scale to their input, and an overrun keeps its findings (October 17)
- Risk scoring gains capability interactions (October 17)
- OCSF events always carry the required `time` attribute (October 17)
- Lint, tests and tooling (October 17)
- README: benchmark chart generated from the committed ShadowBench cases run (October 16)
- Plugin workers no longer see the raw identity key (October 16)
- Integration review fixes (October 15)
- Cap runtime dep ranges at the next major (October 15)
- Per-connector private-origin grants, block-scalar opaque secrets, threat model (October 15)
- Filesystem connector helpers move into bounded modules (October 15)
- Bounded DNS resolution and a typed HttpClient session seam (October 15)
- Black Duck job requires a reviewed Bridge CLI pin (October 15)
- Review hardening: redaction, clone mode, output paths, SARIF and diagnostics (October 15)
- Security hardening: plugin isolation, pre-clone DNS check, exit watchdog (October 15)
- Collection completeness and registry assurance (October 15)
- Medium-severity review corrections
- Review-driven hardening: redaction, SSRF, parser cost, detection coverage (October 15)
- Runtime identity, collection completeness and semantic fallback (October 15)
- README: why and how first, AI-assisted benchmark authorship (October 15)
- README restructured as a landing page (October 15)
- README visuals generated from the code (October 15)
- Redaction review fixes, second round (October 14)
- Whole-branch review fixes (October 14)
- Bounded evidence analysis across connectors (October 14)
- Detection precision, ambiguous app names and scoped correlation (October 14)
- Kubernetes discovery and Atlassian approval scope (October 14)
- Redaction review fixes (October 14)
- ShadowBench review fixes (October 14)
- Repository rename, source distribution and README matrix: review fixes (October 14)
- Dependency refresh and repository hygiene (October 14)
- Repository rename, source distribution and README detection matrix (October 14)
- ShadowBench, the nine-surface discovery benchmark (October 12)
- Documentation aligned with the code (October 12)
- Post-merge review fixes (October 11)
- Command-line and documentation corrections (October 11)
- Integration review corrections (October 11)
- Review corrections after the October 10 integration
- AI-assisted review gate
- Fleet dashboard and inventory export
- Triage, plugin identity, redaction and cache integrity hardening
- Redaction on CPython 3.12.0 to 3.12.3
- Integration review corrections (#178)
- Operational controls guide
- Fleet shadow status, triage budget and CI corrections
- Control evidence report and declared governance facts
- Drift classes, baseline pinning and weekly drift templates
- Threat and control references
- Vendor registry records and trusted registries
- MCP registry provenance and approved MCP catalogs
- Google Agent Registry and Gemini Enterprise catalogs in cloud.gcp
- AWS Agent Registry and AgentCore registry records in cloud.aws
- Microsoft Agent 365, Entra Agent ID and delegated Graph auth in identity.entra
- Autonomy tiers and Capability Card schema version 2
- A2A Agent Card probe and card signatures
- Attested collection scope for live cloud.aws, cloud.azure, cloud.gcp and identity.entra scans
- Scan evidence, completeness and replay corrections
- Discovery classification and lifecycle identity corrections
- Discovery attribution and review assurance
- Verified discovery review corrections
- Source identity, guarded import and AWS command review fixes
- Endpoint, fleet and instruction-content corrections
- October 8 benchmark follow-ups
- Change-scoped scans, path context, corroboration and new ecosystems
- PR review: incremental scan and evidence verification
- Real-world benchmark follow-up corrections
- Real-world robustness: input-defect taxonomy for code.filesystem
- Lexing, matching and walk-order robustness (real-world benchmark fixes)
- Classification and precision
- New capabilities
- Real-world benchmark v2 runner hardening
- Lexical coverage: two constructs the lexer wrongly called ambiguous
- Real-world benchmark follow-up fixes
- Real-world benchmark follow-ups
- Shadow AI discovery benchmark follow-ups
- Shadow AI agent discovery benchmark
- Signatures
- code.filesystem
- CycloneDX
- Real-world benchmark follow-ups: fail-closed corrections

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

The first published release. One line per change; the engineering log has
each entry in full.

- October 8 release tags without a personal signing key
- October 7 release merge-rule check with an administrator readback
- October 7 PyPI distribution and publishing
- Incomplete A2A cards, OpenClaw state files and short sk- keys
- README command checks
- Surface descriptions and pre-commit hooks
- October 6 merge-policy audit diagnostics
- October 6 head-to-head benchmark follow-ups
- Offline runtime inventory connectors
- Security-review follow-ups
- October 3 live merge-policy drift audit
- October 3 keyed credential evidence and invisible-character publication
- October 3 source capability attribution
- October 3 review remediation
- October 3 incremental enumeration-budget review
- October 3 merge integration hygiene
- Bounded source-directory enumeration
- October 3 incremental metadata confinement
- October 3 secret-gate hygiene review
- October 2 follow-ups to #135
- October 2 integration of #134 and repository hygiene review
- October 2 integrity and capability corrections
- October 2 integration of the open pull requests
- October 2 review fixes (AI-assisted, not independently reviewed)
- October 2 production review corrections
- Code structure and developer experience
- October 2 production hygiene review
- October 2 review remediation
- October 2 review corrections
- October 1 scan integrity remediation
- October 1 review corrections
- October 1 review remediation
- October 1 review fixes: bounded matching, link walks and record tolerance
- Confined file portability and plugin deadlines
- October 2 repository hygiene
- October 1 discovery review corrections
- October 1 code.filesystem coverage and precision
- October 1 field scan follow-up
- Completeness, report safety and credential policy (2026-09-28)
- September 28 repository hygiene
- September 27 review follow-up
- September 27 review corrections
- Self-graded audit follow-up
- Field-review follow-up
- Report output safety
- Repository hygiene
- Type checking and lint coverage
- Field review of public repositories (2026-09-25)
- Coverage and release verification follow-up
- Scanner boundaries and acceptance consistency
- Markdown report safety
- Supported-platform preflight
- Community policy consistency
- Private holdout and CLI job deadline gates
- Follow-up trust-boundary review (2026-09-24)
- Control-assurance fixes (2026-09-24)
- Scanner assurance and release evidence (2026-09-25)
- Detection precision, coverage policy and risk explainability
- Quality, precision and governance pass (2026-09-24)
- Production acceptance fixes (2026-09-25)
- Production review round 2 (2026-09-24)
- Detection and collection assurance (2026-09-24)
- Final reconciliation after PR #33 (2026-09-24)
- Security
- Reliability
- Operations

## Earlier hardening notes — 2026-09-24

The following summarizes the reconciled pre-release implementation.

### Security


- Escaped, multiline and nested sensitive mapping values are redacted before source evidence is emitted; TLS verification rejects all falsy effective settings.
- Live AWS account attribution is checked through STS even with a configured expected account.
- Report imports reject ambiguous JSON, unsafe file paths and invalid security attributes before generating inventory stubs.
- GitHub/GitLab API downloads use enumerated immutable blob IDs; links, submodules and malformed Base64 produce incomplete coverage.
- Accountless short AWS IDs cannot approve a registry entry; their scans report incomplete coverage until an account is supplied.
- Filesystem scans reject symlinked root paths and report skipped in-scope symbolic links as incomplete coverage.
- Injected HTTP sessions cannot retain origin-specific adapters that bypass destination checks; default buffered responses have a decoded-byte limit.
- Scan configuration rejects missing required environment values, duplicate authored YAML keys, invalid gate settings, and unsupported top-level options.
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Identity/low-code pagination retains valid neighbors and partial observations, rejects provider failures, and recognizes documented Google empty-list envelopes.
- GCP Cloud Run lists concrete locations; unreachable regions are incomplete. Azure ARM pages preserve observations while incomplete diagnostic collections remain unknown.
- AWS and OCI SDK clients use finite transport/retry bounds; AWS Lambda and GCP project limits stop enumeration early.
- Relative inventory globs and work directories resolve beside their configuration file.
- A later Azure Resource Graph page failure retains already observed resources and reports incomplete coverage; GCP caller attribution is scoped by project.
- Concurrent connector completion order no longer determines merged finding ownership or metadata.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Repeated gateway headers reuse bounded per-scan classification summaries; regex contention retries retain their original CPU and input deadlines.
- Docker build context uses an explicit input allowlist, Actions checkout drops persisted credentials, and both CI matrix jobs finish independently.
- Incremental fingerprints ignore literal excluded source directories while retaining CODEOWNERS inputs; project-root attribution scales with active ancestors in wide monorepos.
- Disposable non-root worker image (`Dockerfile`).
- CI runs lint, audit, test, and package checks in each Python matrix job, with a concurrency group.
- Example GitHub Action and README use commit-pinned install examples and document incomplete-scan gating.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change with these commits. Rebuild comparison baselines and incremental state when upgrading from an earlier revision.
- Install from a reviewed tag/SHA. Do not follow `main`.

### Known limits
- Connector deadlines are cooperative; blocked SDK/plugin calls still need host process timeouts.
- SDK timeouts and retry limits do not establish a universal deadline for authentication chains or whole scans; workers still require a host deadline.
- Incremental cache writes are atomic and protected by per-slot advisory locks on POSIX. Unsupported platforms and contention use full scans.
