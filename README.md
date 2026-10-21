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

This README describes the current source branch, including changes not yet
published on PyPI. For the published alpha, see the
[0.1.3 documentation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/v0.1.3/README.md).
Newer commands require a
[reviewed source installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).

---

## Why ShadowScan

Agents are no longer only Python scripts.
They are Copilot Studio bots built by HR, `n8n` flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock Agents provisioned by Terraform, MCP servers wired into every
developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs carrying an `act` claim.
ShadowScan normalizes these observations into one finding model with evidence,
so investigators or auditors can ask: *Who owns this AI Agent? What can it do, and is it
registered in the agent registry supplied for this scan?*

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

Detection knowledge lives in YAML signature packs and threat and control
references in YAML mapping catalogs, so adding a product is a data change, not
a code change.

Collection and analysis fail closed: an API error, a timeout,
a refused page, an unparseable manifest or a malformed export marks the scan
incomplete (exit 3) rather than producing a smaller report that looks clean.
A gap the scanner can bound — a handful of unreadable entries in a large tree
— is instead charged against a 2% coverage budget (`--max-coverage-gap`,
`strict_coverage` to disable) and counted in the JSON report's
`stats[].coverage` whether or not it changes the exit code; the first 50 are
listed under `stats[].coverage.details`, and `details_truncated` counts the
rest. Only the opt-in LLM triage is advisory; its failures are warnings and it
never changes scores. See
[architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md)
for the pipeline, the package layout and the connector contract.

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

## Benchmarks

**Nexus ShadowScan is currently the best-in-class open-source shadow AI scanner on
ShadowBench.** In each run below it has the highest score on that run's headline
metric of the open-source tools tested, and in the two multi-surface runs it is the
only tool that covers every surface. These benchmarks were developed in this
repository and have since moved, byte-for-byte, to
[Nexus ShadowBench](https://github.com/aisecnomad/Nexus-ShadowBench), which `main`
pins as the `benchmark-suite` submodule. The figures below are those committed
runs; none was rerun or regraded in the move.

| Run | Inputs | ShadowScan | Next-best open-source tool, same metric |
|---|---|---|---|
| [Head-to-head](https://github.com/aisecnomad/Nexus-ShadowBench/blob/e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e/tools/benchmark/results/REPORT.md) (tools pinned 2026-10-06) | 900 synthetic cases: repository, endpoint, network | Estate recall 0.90 (0.87–0.92) | Cisco AI BOM 0.49 (0.45–0.53) |
| [ShadowBench cases](https://github.com/aisecnomad/Nexus-ShadowBench/blob/e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e/benchmarks/shadowbench/cases/results/2026-10-11/REPORT.md) (2026-10-11) | 346 cases, 738 entities, nine surfaces | Estate recall 0.839 | AI-Infra-Guard, AgentDiscover 0.035 |
| [Shadow AI discovery](https://github.com/aisecnomad/Nexus-ShadowBench/blob/e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e/benchmarks/shadow-ai-discovery/results/2026-10-09/REPORT.md) (2026-10-09) | 87 public repositories, code surface | In-scope value F1 0.972 | NuGuard 0.750 |

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/benchmarks-head-to-head.webp" alt="Head-to-head estate recall on 900 synthetic cases: ShadowScan 0.90, Cisco AI BOM 0.49, AgentSonar 0.33, agent-bom 0.29, Shadow AI Detector 0.28, AgentDiscover 0.23, Open Shadow AI 0.19, Snyk Agent Scan 0.18, AI-Detector 0.13, Cisco MCP Scanner 0.04, Claw-Hunter 0.04" width="95%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/benchmarks-cross-tool.webp" alt="Left: ShadowBench cases estate recall, ShadowScan 0.839 against 0.035 or less for every other tool. Right: Shadow AI discovery value-level F1, ShadowScan 0.972, NuGuard 0.750, SafeDep vet 0.587, Trusera ai-bom 0.585, cdxgen 0.511" width="95%">
</p>

These results are evidence about the listed inputs. They are **not** independent
review and **not** measured field accuracy. The maintainer wrote every corpus,
label, scorer and tool adapter. The head-to-head was pre-registered, with
ShadowScan's results committed before any other tool ran. The cases run was
re-scored after the run with its results in view. The discovery result is
in-sample: the 0.972 F1 was measured after tuning on that corpus
([0.909 before](https://github.com/aisecnomad/Nexus-ShadowBench/blob/e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e/benchmarks/shadow-ai-discovery/results/2026-10-08/REPORT.md)).
Estate recall charges each tool for the surfaces it does not
cover, so it mostly measures coverage: compare tools on the in-scope columns in each
report, not on these headline numbers. Several tools ran below full capability.

ShadowScan still has gaps. It found 70% of AI developer home directories in the
head-to-head, its specificity on decoys in the cases run was 63%, and it marked 27
of its 326 scans in the cases run and 43 of 87 in the discovery run incomplete.
Not every ShadowBench run favors it: in three
[real-world repository runs](https://github.com/aisecnomad/Nexus-ShadowBench/blob/e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e/benchmarks/README.md)
from 2026-10-08 (34, 41 and 326 public repositories), other tools scored higher,
partly because those runs count ShadowScan's incomplete scans as misses. See
[benchmark evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md#benchmarks)
for per-surface results and limits.

---

## Install

```bash
pip install NexusShadowScan                  # or: pipx install NexusShadowScan
pip install "NexusShadowScan[cloud]"         # adds AWS, GCP, Azure, and OCI SDKs
shadowscan --help
```

> **PyPI 0.1.3 requirements:** Python 3.11, 3.12, 3.13 or 3.14, the same
> interpreters as current source.
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

`agent-card.yaml`, `examples/` and the sample exports under `tests/fixtures/`
come from a repository checkout; the wheel does not ship them. Scanning the
ShadowScan checkout itself with `shadowscan code .` reports an incomplete scan
(exit 3): a few redaction test files are built to exceed the sanitizer's own
safety limits, and a finding the sanitizer cannot bound is withheld rather than
published unredacted — that is unbounded, so no budget applies to it. Its handful
of unreadable entries, by contrast, stay within the coverage budget. In a
checkout, `make self-scan` runs `examples/shadowscan.self-scan.yaml`, which
excludes those paths, each with a documented reason, and completes with exit 0;
`shadowscan code tests/fixtures/sample_repo --inventory agent-card.yaml`
scans the bundled sample repository in seconds.

See the [quick start guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md)
for walkthroughs of each surface and the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) for all options.

## Commands and exit codes

Run `shadowscan --help` or `shadowscan <command> --help` for the installed version.

| Task | Command |
|---|---|
| Local repository | `shadowscan code .` |
| Check local inputs | `shadowscan code . --preflight` |
| Staged Git files | `shadowscan code --quick` |
| GitHub repositories | `shadowscan run code.github --set repos=OWNER/REPO` |
| Configured estate | `shadowscan scan -c shadowscan.yaml` |
| Compare JSON reports | `shadowscan diff baseline.json current.json` |
| Browse a JSON report | `shadowscan triage report.json` |
| Fleet dashboard | `shadowscan dashboard report.json -o dashboard.html` |
| Available connectors | `shadowscan connectors` |

| Exit | Meaning |
|---|---|
| 0 | Complete for the declared scope and within the configured policy |
| 1 | Setup, configuration, input or output failure; no usable scan result |
| 2 | Complete scan reached `--fail-on`, or a requested drift threshold |
| 3 | Incomplete scan or comparison; inspect the report before relying on it |

API errors, denied access, timeouts and unbounded analysis or sanitization limits
remain incomplete. A tolerated, bounded gap remains visible in the JSON coverage
ledger. A complete static scan does not prove that no agent runs.
For exit 3, start with [incomplete-scan troubleshooting](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/incomplete-scans.md).
See [scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md).

## Documentation

| Topic | Reference |
|---|---|
| Installation and first scan | [Installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md), [quick start](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md) |
| Options and configuration | [CLI reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md), [configuration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) |
| Examples, output and detection | [Product guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md), [connector reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors/reference.md) |
| Python integration | [API reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/api/index.md) |
| Benchmark protocols and limitations | [Benchmark evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md#benchmarks) |
| Production use and trust boundaries | [Deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md), [threat model](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/threat-model.md) |

Benchmark and evaluation results are evidence about the listed inputs. They are
not independent review or measured production precision. Corpora used to tune
detection are in-sample; review the disclosed incomplete runs and per-surface
limits before interpreting their scores.

## Project status

* **Release state.** Version `0.1.3` is published to PyPI as `NexusShadowScan`
  and tagged `v0.1.3`, as an alpha pre-release. Confirm the artifact identity
  on [PyPI](https://pypi.org/project/NexusShadowScan/0.1.3/) and the
  [GitHub release](https://github.com/aisecnomad/Nexus-ShadowScan/releases/tag/v0.1.3)
  before installing it. The package classifier is `Development Status :: 3 - Alpha`.
  Commits on `main` after the tag are unreleased. Publication does not
  establish independent review or deployment acceptance.
* **Single maintainer, AI-assisted development.** Apart from Dependabot updates, every commit was written
  by a single maintainer or generated with an AI coding assistant (Claude, Codex, Grok, GitHub Copilot, Google Antigravity, Perplexity, Meta AI, etc.). The logs under
  [archive/reviews/](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/archive/reviews) are AI-assisted, not third-party reviews.
* **Recommendation.** Review the revision yourself or have it reviewed, then
  pin that full commit SHA as shown in
  [Deployment install](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).
  Review state cannot be established from a checkout; verify it with the
  commands in
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
| See what changed or cite the project | [Release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md), [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [Engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

Use synthetic, minimal examples in public reports. Scan results can contain
credentials, personal data, and sensitive inventory even after redaction.

## Safety and security notes

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data.
* Secret stores (Secrets Manager, Key Vault, Secret Manager, OCI Vault) are read for **names only**.
* JWTs are never persisted; findings reference a truncated hash.
* Built-in collectors inspect provider resources using read operations. Scope the audit identity to the documented read permissions and review any enabled third-party plugin separately.

See [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md) and [docs/production.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md) for deployment behavior, migration and limits.

## License

Apache-2.0. See [LICENSE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and [NOTICE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE).
