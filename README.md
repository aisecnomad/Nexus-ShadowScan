<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/hero-banner.svg" alt="Nexus ShadowScan — open-source AI agent discovery" width="100%">
</p>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-ShadowScan"><img src="https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-ShadowScan/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11-3.14"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates"><img src="https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen.svg" alt="Coverage >= 80%"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/docs"><img src="https://img.shields.io/badge/docs-source-blue.svg" alt="Docs"></a>
  <a href="https://pypi.org/project/NexusShadowScan/"><img src="https://img.shields.io/pypi/v/NexusShadowScan.svg" alt="PyPI: NexusShadowScan"></a>
</p>

<p align="center"><strong>Discover evidence of shadow AI agents across your organization and reconcile it against your approved agent registry.</strong></p>

<p align="center">
It inspects nine surfaces: code repositories, identity providers, LLM gateway logs,
low-code platforms, SaaS apps, cloud accounts, endpoints (developer workstations and
host/runtime inventories), network logs, and running processes.
</p>

| GitHub repository | PyPI distribution | Command and Python package |
|---|---|---|
| [`aisecnomad/Nexus-ShadowScan`](https://github.com/aisecnomad/Nexus-ShadowScan) | [`NexusShadowScan`](https://pypi.org/project/NexusShadowScan/) | `shadowscan` |

> The repository was formerly `aisecnomad/Project-Nexus`; GitHub redirects the old links.

This README describes the current source branch, including changes not yet published on PyPI. For the
published alpha, see the [0.1.2 documentation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/v0.1.2/README.md).
Newer commands require a
[reviewed source installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).

## Why ShadowScan

Agents are no longer only Python scripts. They are Copilot Studio bots built by HR, `n8n` flows with an *AI
Agent* node, OAuth grants to meeting note-takers, Bedrock Agents provisioned by Terraform, MCP servers wired
into every developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs
carrying an `act` claim. ShadowScan normalizes these observations into one finding model with evidence, so
investigators or auditors can ask: *Who owns this AI Agent? What can it do, and is it registered in the
agent registry supplied for this scan?*

| Observation | What it establishes | Next check |
|---|---|---|
| Source dependency, import, or configuration | A repository contains a potential integration. | Inspect executable code and deployment; comments, examples, and unused dependencies can mislead. |
| Cloud or SaaS resource | The collector observed a configured resource within its granted scope. | Check resource state and authenticated runtime telemetry before claiming execution. |
| Gateway event | The supplied log contains a request or tool-use signal. | Verify the log's origin, caller binding, and observation window before attributing it to a deployed agent. |
| `shadow: true` | No single explicit binding in the **supplied** inventory matched the finding. | Confirm the inventory's scope and freshness; an unmatched finding alone does not prove unauthorized use. |

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/architecture-data-flow.svg" alt="Nexus ShadowScan architecture: connectors collect per surface, analysis and correlation score findings, reconciliation compares them with the sanctioned inventory" width="95%">
</p>

```
connectors ── live API (collect) or offline export (input) ──► records
records ── analyze() against YAML signature packs ──► findings with evidence
findings ── merge ─► correlate across surfaces ─► reconcile with inventory and trusted
            registries ─► classify autonomy ─► score risk ─► (opt-in) LLM triage
report ──── table · json · sarif · csv · markdown · html · cyclonedx · ocsf
JSON reports ── diff · merge (fleet) · dashboard · controls · inventory stubs
```

Detection knowledge lives in YAML signature packs and threat and control references in YAML mapping
catalogs, so adding a product is a data change, not a code change. The sanctioned inventory is a directory
of [Agent Cards](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/agent-card.yaml), `agents.yaml`
lists or CSV; `shadowscan inventory stubs` drafts cards from shadow findings.

**Fail-closed contract.** Collection and analysis fail closed: an API error, a timeout, a refused page, an
unparseable manifest or a malformed export marks the scan incomplete (exit 3) rather than producing a
smaller report that looks clean. A gap the scanner can bound — a handful of unreadable entries in a large
tree — is instead charged against a 2% coverage budget (`--max-coverage-gap`, `strict_coverage` to disable)
and counted in the JSON report's `stats[].coverage` whether or not it changes the exit code; the first 50
are listed under `stats[].coverage.details`, and `details_truncated` counts the rest. Only the opt-in LLM
triage is advisory; its failures are warnings and it never changes scores. See
[scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md#coverage-policy)
and [architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md).

## Key capabilities

| Capability | Details |
|---|---|
| **38 connectors** across 9 surfaces | Code, Identity, Gateway, Low-code, SaaS, Cloud, Endpoint, Network, Runtime |
| **233 signatures / 1133 signals** | Orchestrators, protocols, coding agents, platforms, model providers, AI SaaS apps, permission policies |
| **Live and offline modes** | 28 of the 38 connectors collect from a live API with credentials; all 38 replay offline JSON/CSV/log exports. The other 10 are replay-only by nature (Kubernetes/OpenShift manifest dumps, gateway and network logs, OTel traces, endpoint inventories, generic SaaS exports) — they read an export something else produced |
| **8 output formats** | `table` · `json` · `sarif` · `csv` · `markdown` · `html` · `cyclonedx` · `ocsf` |
| **Risk scoring** | Additive, explainable 0-100 score with per-factor breakdown |
| **Autonomy classification** | L0 (Chatbot) through L5 (Fully Autonomous) interval |
| **Inventory reconciliation** | Agent Cards, `agents.yaml` lists, CSV inventories |
| **Threat & control mappings** | OWASP ASI, OWASP LLM, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act, AIUC-1 |
| **Fleet operations** | Merge reports, dashboard, diff for drift detection, control evidence |
| **CI/CD integration** | GitHub Actions SARIF upload, deterministic exit codes, drift gating |
| **Fail-closed design** | Errors, timeouts and unbounded gaps produce exit 3 (incomplete), never a smaller clean report. Bounded gaps are budgeted (2% of entries by default) and always reported |
| **Credential safety** | Known credential formats redacted before persistence; secret stores read for names only |

## Install

```bash
pip install NexusShadowScan                  # or: pipx install NexusShadowScan
pip install "NexusShadowScan[cloud]"         # adds AWS, GCP, Azure, and OCI SDKs
shadowscan --help
```

> **PyPI 0.1.2 requirements:** Python 3.11–3.13. Current source supports
> Python 3.11, 3.12, 3.13 or 3.14; Python 3.14 support is not in that release.
>
> The distribution is `NexusShadowScan`; the unrelated `shadowscan` package on
> PyPI is not this project. Releases are uploaded through PyPI trusted publishing
> and attested on GitHub, so you can check a download with `gh attestation verify`.
> For a deployment, install a reviewed commit from the hash-locks instead; both
> procedures are in the
> [installation guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md).

## Quick start

```bash
# 1. Scan a local repository — no credentials needed
shadowscan code .
# 2. Try every connector offline with bundled fixtures (36 of 38 connectors ship fixtures; needs a checkout)
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html
# 3. Live estate scan with secrets from the environment
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif
# 4. Scan only PR changes (Git 2.45+)
shadowscan code . --diff-base origin/main
# 5. Scan developer workstations for AI clients
shadowscan endpoint
# 6. Analyze gateway logs
shadowscan gateway access.log litellm-spend.jsonl
# 7. Classify JWTs as human, service, or agent
shadowscan jwt --file tokens.txt --jwks-url https://login.example.com/.well-known/jwks.json
```

Abridged offline demo (`--max-rows 5` shows the five highest-risk rows):

```
$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 5

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 132 findings  •  128 shadow (inventory: 4 registered agents)               │
│ critical 16  high 51  medium 64  low 1                                     │
│ cloud 30 identity 19 endpoint 18 …                                         │
╰────────────────────────────────────────────────────────────────────────────╯
 CRITICAL 100  SHADOW  code     agent-config Claude Code configured in repository root
 CRITICAL 100  SHADOW  code     mcp-server   MCP configuration: .mcp.json
 CRITICAL  94  SHADOW  lowcode  agent        ServiceNow AI agent: Incident Triage Agent
 CRITICAL  91  SHADOW  endpoint agent-config OpenClaw configured on dev-laptop-07 (~dana)
 CRITICAL  90  SHADOW  code     agent        Agent in services/research-agent: LangGraph, LangChain, Model Context Protocol (MCP)
```

`agent-card.yaml`, `examples/` and `tests/fixtures/` come from a repository checkout; the wheel does not
ship them. `shadowscan code .` on the ShadowScan checkout itself exits 3 on purpose; `make self-scan` scans
it with documented exclusions and exits 0. The
[quick start guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md)
covers each surface, reading a finding and the Python API, and the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md)
every option.

## Command reference

| Command | Purpose |
|---|---|
| `shadowscan code [PATHS...]` | Scan repos for agent frameworks, MCP, coding agents, IaC, secrets |
| `shadowscan scan -c CONFIG` | Run every connector in a YAML config file |
| `shadowscan run CONNECTOR` | Run a single connector ad-hoc (`--set key=val`) |
| `shadowscan endpoint` | Scan workstation AI clients (Claude, Cursor, Windsurf, Ollama, …) |
| `shadowscan gateway LOGS...` | Analyze LLM gateway / provider / proxy logs |
| `shadowscan jwt [TOKENS...]` | Classify JWTs as human, service, or agent |
| `shadowscan merge REPORTS...` | Combine JSON reports into one fleet report |
| `shadowscan dashboard REPORTS...` | Write a static fleet dashboard (HTML + optional inventory JSON) |
| `shadowscan diff BASE CURRENT` | Compare reports for new, resolved, and drifted findings |
| `shadowscan controls REPORTS...` | Map findings to NIST AI RMF / ISO 42001 / EU AI Act / AIUC-1 controls |
| `shadowscan inventory check` | Validate Agent Card / agents.yaml / CSV inventory files |
| `shadowscan inventory stubs` | Generate Agent Card skeletons from shadow findings |
| `shadowscan mcp-registry snapshot` | Pin an MCP registry into a versioned snapshot |
| `shadowscan signatures list\|show\|test` | Inspect and test detection signature packs |
| `shadowscan connectors` | List available connectors, config keys, and offline formats |

Every scan command accepts `-f/--format`, `-o/--output`, `-i/--inventory`, `-s/--signatures`, `--fail-on`,
`--min-confidence`, `--dump-records`, `--incremental`, `--job-deadline-seconds`, and security boundary
flags. The
[command reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md)
documents every command, option and
[output format](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md#output-formats);
`shadowscan <command> --help` prints them for the installed version.

## Exit codes

| Exit | Meaning |
|---|---|
| **0** | Scan completed and passed |
| **1** | No scan result: invalid option, value, path or configuration, or a setup or output error |
| **2** | Scan completed but reached `--fail-on`; `diff` returns 2 with `--fail-on-new` or `--fail-on-drift` |
| **3** | Scan incomplete (API error, timeout, denied access, limit, malformed export); `diff` returns 3 when reports are not comparable |

Gate CI on any non-zero exit: exit 1 means nothing was scanned, and an incomplete scan never reads as clean.
On exit 3 the CLI names the reason categories on stderr (`scan incomplete (exit 3): oversize-file 2`), and
the report counts them in `summary.incomplete_reasons`; `shadowscan code --profile ci` declares the gaps a
source gate accepts (dangling test certificate links, malformed fixtures, generated code) in advance and
counts them in `summary.declared_omissions`, never one that left a file unread for credentials. Exit 0 from
a complete static scan does not prove that no agent runs; see
[scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md).

## Surfaces & connectors

| Surface | Connectors | What is discovered |
|---|---|---|
| **Code** | `code.filesystem`, `code.github`, `code.gitlab` | Agent frameworks & LLM SDKs (deps, imports, idioms), MCP client/server configs, coding-agent configs, A2A agent cards, IaC provisioning, CI secrets, hard-coded provider keys (redacted) |
| **Identity** | `identity.okta`, `identity.entra`, `identity.google-workspace`, `identity.auth0`, `identity.jwt` | OAuth apps & consent grants to AI SaaS, service principals / managed identities with LLM or data permissions, JWT classification (human/service/agent) |
| **Gateway** | `gateway.logs`, `gateway.otel` | Callers reconstructed from gateway logs or offline OpenTelemetry GenAI spans; span prompt and completion content is not retained |
| **Low-code** | `lowcode.power-platform`, `lowcode.salesforce`, `lowcode.servicenow`, `lowcode.n8n`, `lowcode.make`, `lowcode.zapier`, `lowcode.workato` | Copilot Studio agents, Agentforce, Now Assist, automation workflows with AI steps |
| **SaaS** | `saas.slack`, `saas.microsoft-teams`, `saas.github-apps`, `saas.atlassian`, `saas.notion`, `saas.zoom`, `saas.generic` | Bots and apps with their scopes, install requests, AI coding agents and their permissions |
| **Cloud** | `cloud.aws`, `cloud.gcp`, `cloud.azure`, `cloud.oci`, `cloud.kubernetes`, `cloud.openshift` | Managed cloud AI and IAM inventories, Kubernetes/OpenShift workload exports |
| **Endpoint** | `endpoint.inventory`, `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models`, `endpoint.ebpf` | AI clients and coding agents on workstations with their MCP servers, local model stores, osquery fleet exports |
| **Network** | `network.logs` | AI services contacted per client address from DNS, TLS SNI and flow logs |
| **Runtime** | `runtime.processes` | Coding-agent CLIs, AI apps, MCP servers and local model servers seen running; command lines are never kept |

The [detection matrix](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/detection-matrix.md)
lists the frameworks, MCP evidence and connectors recognized, generated from the shipped packs; the
[connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) gives modes, scopes and export formats.

## Benchmarks

The maintainer wrote ShadowScan, the benchmark corpora, their labels and the harnesses with AI
coding assistants, so the numbers are regression evidence about those inputs, **not** independent
review and **not** measured production precision or recall; runs on a corpus ShadowScan was tuned
against are in-sample. Results, per-surface weak spots and charts are on the
[evaluation page](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md#benchmark-results);
the [benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md) gives each protocol and its limits.

## Documentation

The [`docs/`](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/docs)
directory of the revision you run is the source of truth.

| Topic | Pages |
|---|---|
| Getting started | [Installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md), [quick start](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md), [configuration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md), [command reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md), [detection matrix](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/detection-matrix.md) |
| How it works | [Architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md), [scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md), [signatures](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/signatures.md), [design decisions (ADRs)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/adrs/index.md) |
| Connectors and extending | [Connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md), [configuration key reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors/reference.md), [writing a connector](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md#writing-a-connector), [third-party plugin execution](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md#third-party-plugin-execution) |
| Assessment | [Inventory](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/inventory.md), [risk scoring](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/risk.md), [autonomy tiers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/autonomy.md), [threat and control mappings](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/mappings.md), [severity](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md) |
| Operations | [CI integration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ci.md), [scheduled drift](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/drift.md), [fleet dashboard](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/dashboard.md), [control evidence report](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/controls.md), [AI-BOM](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ai-bom.md), [OCSF](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ocsf.md), [LLM triage](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/llm-triage.md) |
| Deployment and assurance | [Production deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md), [evaluation and benchmarks](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md), [tenant canaries](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/canaries.md), [external reviewer packet](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/reviewer-packet.md) |
| Security | [Security policy](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md), [threat model](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/threat-model.md), [controls and limits](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/controls.md), [redaction](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/redaction.md), [hardening log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/hardening-log.md) |
| Python API and development | [API reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/api/index.md), [testing and Make targets](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/testing.md), [contributor guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#getting-started) and its [repository map](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#find-your-way-around) |

## Project status

* **Release state.** Version `0.1.2` is published to PyPI as `NexusShadowScan` and tagged `v0.1.2`, as an alpha
  pre-release. The package classifier is `Development Status :: 3 - Alpha`. Commits on `main` after the tag are
  unreleased. Publication does not establish independent review or deployment acceptance.
* **Single maintainer, AI-assisted development.** Apart from Dependabot updates, every commit was written
  by a single maintainer or generated with an AI coding assistant (Claude, Codex, Grok, GitHub Copilot, Google Antigravity, Perplexity, Meta AI, etc.). The logs under
  [archive/reviews/](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/archive/reviews) are AI-assisted, not third-party reviews.
* **Evidence limits.** Corpora, benchmarks and assurance results are author-written or AI-labeled, and offline replay is not
  live tenant acceptance; see [evidence and assurance limits](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md#evidence-and-assurance-limits).
* **Recommendation.** Review the revision yourself or have it reviewed, then pin that full commit SHA as shown in
  [Deployment install](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).
  Review state cannot be established from a checkout; verify it with the commands in
  [merge gate and review status](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#merge-gate-and-review-status).

## Community and contributing

| I want to… | Start here |
|---|---|
| Ask a question or troubleshoot | [Support guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) |
| Report a bug or request a feature | [Issue forms](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new/choose) |
| Report a false positive or missed framework | [Detection quality report](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=detection_report.yml) |
| Make a first contribution | [Contributor guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md) and [`good first issue`](https://github.com/aisecnomad/Nexus-ShadowScan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) |
| Report a vulnerability privately | [Security policy](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#reporting) |
| Understand decisions, review and release requirements | [Governance](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md), [Maintainers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/MAINTAINERS.md), [Roadmap](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/ROADMAP.md) |
| Understand participation standards | [Code of conduct](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CODE_OF_CONDUCT.md) |
| See what changed or cite the project | [Release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/release-notes.md), [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [Engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

Use synthetic, minimal examples in public reports. Scan results can contain
credentials, personal data, and sensitive inventory even after redaction.

## Security

Known credential formats are redacted before findings or record exports are persisted, secret
stores are read for names only and JWTs are never persisted; redaction cannot identify every
secret, so treat reports as sensitive. Report vulnerabilities privately as
[SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md) describes; see
[redaction](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/redaction.md) and
[production deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md) for limits.

## License

Apache-2.0. See [LICENSE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and [NOTICE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE).
