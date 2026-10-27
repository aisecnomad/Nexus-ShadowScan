# Roadmap

ShadowScan 0.1.4 is the published alpha release (`NexusShadowScan` on
PyPI, tag `v0.1.4`); `main` carries unreleased changes. This roadmap is
intent, not a contract. Items move only when they keep the
fail-closed trust model.

## Now

- Keep community standards complete: code of conduct, support routing,
  issue forms, Scorecard, and honest maintainer status.
- Keep the README Scorecard badge in sync with published `main` results. The
  score is not independent review.
- Freeze a review-candidate SHA before further hardening bursts. External
  reviewers should start from
  [docs/operations/reviewer-packet.md](docs/operations/reviewer-packet.md).
  Completing the packet is not a release approval.
- Grow the first-contribution surface: documentation, signatures, offline
  fixtures, evaluation cases.
- Recruit an independent reviewer who can satisfy the non-author approval rule
  and review the exact release candidate.
- Complete fresh human-labeled holdout and scope-specific live tenant
  acceptance; retain the evidence before enabling enforcement.
- Finish enforcing the versioned [merge policy](docs/operations/merge-policy.md)
  on `main` and exercise the manual release-evidence workflow after the
  candidate is reviewed and merged. The 2026-10-10 readback showed `CI gate`,
  the GitHub Actions binding on every required check, last-push approval and
  review-thread resolution live-required, but also four `always` bypass
  actors on both rulesets. The
  [2026-10-18](docs/operations/merge-policy.md#october-18-readback) and
  [2026-10-26](docs/operations/merge-policy.md#october-26-readback) readbacks
  show `bypass_actors: []` on both `main` rulesets and on the release-tag
  ruleset, with settings matching the committed payloads. A readback is a
  point-in-time observation, not evidence of continuous enforcement; repeat it
  before each release candidate.

## Next

- Add opt-in live collection where only offline exports are read today: the
  Kubernetes and OpenShift APIs, host inventories, confined model-artifact
  inspection, and MCP HTTP inventory probes. Local workstation discovery
  (`shadowscan endpoint`, `endpoint.inventory` without `input`), `/proc`
  process reading (`runtime.processes`) and opt-in A2A Agent Card fetches
  (`endpoint.mcp`) already exist.
- Additional connectors on the existing surfaces, driven by
  [connector requests](https://github.com/aisecnomad/Nexus-ShadowScan/issues?q=label%3Aconnector-request).
- Field validation of the endpoint, network and runtime connectors on real
  osquery, Zeek, VPC and EDR exports, and a measured evaluation of LLM triage
  verdicts before anyone relies on them.
- Tighter Agent Card binding examples and inventory authoring guides.
- Public docs screenshots of the HTML report and SARIF upload path.
- Re-check the OpenSSF Scorecard badge after each `main` Scorecard run.
  Code-Review and Branch-Protection stay at zero until a second reviewer
  exists.
- Point GitHub Pages at the Docs workflow artifact and publish the MkDocs
  site with the existing manual `docs.yml` dispatch. Do not treat the current
  Pages URL as that site.

## Next: agent governance

Scoped, sequenced and with acceptance criteria in
[docs/proposals/agent-governance.md](docs/proposals/agent-governance.md).
All six items below are implemented and released in 0.1.3; they wait on
independent review of that release and on live validation.

- Threat mapping: released in 0.1.3. OWASP LLM and Agentic, MITRE
  ATLAS and MAESTRO references come from edition-pinned, validated catalogs;
  see [docs/concepts/mappings.md](docs/concepts/mappings.md). Independent
  review of the author mappings remains open.
- Autonomy tiers L0 (Chatbot) to L5 (Fully Autonomous), reported as an
  evidence interval (floor and ceiling) and compared with the level a
  schema version 2 Capability Card declares. An unknown tier never counts as
  a low one. The first part is implemented; see
  [docs/concepts/autonomy.md](docs/concepts/autonomy.md). Evaluation corpus
  cases per tier and surface and a comparison with other autonomy frameworks
  remain open.
- Scheduled drift: released in 0.1.3. Live `cloud.aws`, `cloud.azure`,
  `cloud.gcp` and app-only `identity.entra` scans attest their collection
  scope, `diff` labels drift classes (inventory, capability, autonomy,
  governance, coverage, including MCP tool-definition changes), baselines are
  pinned and expire, and weekly workflow and CronJob templates exist; see
  [docs/operations/drift.md](docs/operations/drift.md). Validation against
  live accounts and tenants, and attestation for the other live connectors,
  remain open.
- Registry integrations: released in 0.1.3. AWS AgentCore Registry,
  Microsoft Agent 365 and Gemini Enterprise as discovery and reconciliation
  sources; official MCP Registry provenance and private MCP registry
  allowlists; A2A Agent Card collection. Vendor registry approval never
  confers sanctioned status unless the operator explicitly trusts that
  registry. Validation against live registries remains open.
- Enterprise inventory dashboard: released in 0.1.3. `shadowscan
  dashboard` writes a static, self-contained page from fleet reports that
  shows coverage before counts, with autonomy against shadow status,
  registry reconciliation, reference counts, drift and history, plus the
  versioned `shadowscan.inventory/v1` export for BI and SIEM tools; see
  [docs/operations/dashboard.md](docs/operations/dashboard.md). Use on a
  large live fleet remains to be validated.
- Control mapping: released in 0.1.3. ISO/IEC 42001, NIST AI RMF, the
  EU AI Act and AIUC-1 references, `shadowscan controls` evidence reports and
  declared governance facts in schema version 2 Capability Cards; see
  [docs/operations/controls.md](docs/operations/controls.md). They are
  evidence references labelled as author mappings until independently
  reviewed, never compliance determinations.

## Later, after independent review

- Done: the PyPI trusted publisher is registered, and 0.1.4 is published to
  PyPI as `NexusShadowScan` through the approval-gated trusted-publishing job
  (tag `v0.1.4`). Nothing publishes automatically, and publication does not
  establish independent review or deployment acceptance.
- Next release: a candidate whose exact commit has independent human review
  and retained acceptance evidence for its deployment scope, as the
  [release process](GOVERNANCE.md#release-process) requires, then tagged and
  published by the maintainer following the
  [publishing runbook](docs/operations/publishing.md).
- Add a second required reviewer to the `pypi` and `testpypi` environments and
  turn on **Prevent self-review** as soon as one exists.

## Not planned

- A hosted scanning service or hosted dashboard
- Compliance determinations, certification claims or compliance scores;
  control and threat mappings are evidence references
- Write operations against customer tenants
- Treating heuristic confidence as a calibrated probability
- Weakening redaction, plugin allowlists, or incomplete-scan semantics
  to look more complete
