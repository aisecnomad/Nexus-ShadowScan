<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/84183af55768191b6a4044b424a2e8e57013763a/docs/assets/hero-banner.svg" alt="Nexus ShadowScan — open-source AI agent discovery" width="100%">
</p>

<h1 align="center">Nexus ShadowScan</h1>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-ShadowScan"><img src="https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-ShadowScan/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://pypi.org/project/NexusShadowScan/"><img src="https://img.shields.io/pypi/v/NexusShadowScan.svg" alt="PyPI: NexusShadowScan"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11-3.14"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
</p>

<p align="center"><strong>Discover evidence of shadow AI agents across your organization and reconcile it against your inventory of approved agents.</strong></p>

<p align="center">
It inspects nine surfaces: code repositories, identity providers, LLM gateway logs,
low-code platforms, SaaS apps, cloud accounts, endpoints (developer workstations and
host/runtime inventories), network logs, and running processes.
</p>

> **Alpha software from a single maintainer, built with AI coding assistants.**
> Scans fail closed. Errors, timeouts and unbounded gaps mark a scan incomplete
> (exit 3) instead of producing a smaller report that looks clean, and bounded gaps
> are charged to a coverage budget and reported. A finding marked
> `shadow: true` had no match in the inventory you supplied; that is a lead to
> investigate, not proof of unauthorized use. The benchmarks below were designed,
> run and scored by the maintainer and are not an independent evaluation.

## Install

```bash
pipx install NexusShadowScan                 # or: pip install NexusShadowScan
pip install "NexusShadowScan[cloud]"         # adds AWS, GCP, Azure and OCI libraries
uvx --from NexusShadowScan shadowscan --help # try it without installing
```

**Requirements:** CPython 3.11–3.14 (on 3.12, use 3.12.4 or later). Linux x86_64 is
the validated deployment platform, and macOS is tested for development use.
Windows is not supported: every command except `--help` and `--version` refuses
to run there.

The distribution is `NexusShadowScan`; the command and Python package are
`shadowscan`. The unrelated `shadowscan` package on PyPI is not this project.
Releases are uploaded through PyPI trusted publishing and attested on GitHub, so
you can check a download with `gh attestation verify`. For a deployment, install a
reviewed commit from the hash-locks instead; both procedures are in the
[installation guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md).

## Quick start

No credentials or configuration are needed to scan a repository or this
workstation:

```bash
shadowscan code .                               # a local repository
shadowscan code . --format html -o report.html  # the same scan as an HTML report
shadowscan endpoint                             # this workstation's AI client configuration
```

Exit codes are deterministic: 0 for a complete scan, 2 when a complete scan
reaches `--fail-on`, and 3 when the scan is incomplete
([all exit codes](#commands-and-exit-codes)).

To see every surface at once, run the offline demo from a checkout; 36 of 38 connectors ship fixtures,
and the demo exercises all nine surfaces without credentials:

```bash
git clone https://github.com/aisecnomad/Nexus-ShadowScan && cd Nexus-ShadowScan
python -m venv .venv && . .venv/bin/activate && pip install .
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html
shadowscan code tests/fixtures/sample_repo --inventory agent-card.yaml
```

The terminal summary of the demo (`--max-rows 4` keeps the four highest-risk rows):

```
$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 4

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 133 findings  •  129 shadow (inventory: 4 registered agents)               │
│ critical 16  high 51  medium 65  low 1                                     │
│ cloud 30 identity 19 endpoint 18 …                                         │
╰────────────────────────────────────────────────────────────────────────────╯
 CRITICAL 100  SHADOW  code     agent-config Claude Code configured in repository root
 CRITICAL 100  SHADOW  code     mcp-server   MCP configuration: .mcp.json
 CRITICAL  94  SHADOW  lowcode  agent        ServiceNow AI agent: Incident Triage Agent
 CRITICAL  91  SHADOW  endpoint agent-config OpenClaw configured on dev-laptop-07 (~dana)
```

For your own estate, list the connectors to run in a `shadowscan.yaml` (see the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md)),
keep secrets in the environment, and run
`shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif`. The
[quick start guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md)
walks through each surface.

In a checkout, `make self-scan` scans ShadowScan itself and completes with exit 0.
A plain `shadowscan code .` there exits 3 by design: three files hold more
synthetic credentials than a scan reports per file, and an ordinary clone leaves
the optional `benchmark-suite` submodule uninitialized.

## Why ShadowScan

Agents are no longer only Python scripts.
They are Copilot Studio bots built by HR, `n8n` flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock Agents provisioned by Terraform, MCP servers wired into every
developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs carrying an `act` claim.
ShadowScan normalizes these observations into one finding model with evidence,
so investigators or auditors can ask: *Who owns this AI agent? What can it do, and
is it in the inventory supplied for this scan?*

| Observation | What it establishes | Next check |
|---|---|---|
| Source dependency, import, or configuration | A repository contains a potential integration. | Inspect executable code and deployment; comments, examples, and unused dependencies can mislead. |
| Cloud or SaaS resource | The collector observed a configured resource within its granted scope. | Check resource state and authenticated runtime telemetry before claiming execution. |
| Gateway event | The supplied log contains a request or tool-use signal. | Verify the log's origin, caller binding, and observation window before attributing it to a deployed agent. |
| `shadow: true` | No single explicit binding in the **supplied** inventory matched the finding. | Confirm the inventory's scope and freshness; an unmatched finding alone does not prove unauthorized use. |

The inventory is your list of approved agents (Agent Cards, `agents.yaml` lists
or CSV), passed with `--inventory`. Without an inventory or a trusted registry,
findings are not reconciled: `shadow` is null, not true.

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/84183af55768191b6a4044b424a2e8e57013763a/docs/assets/architecture-data-flow.svg" alt="Nexus ShadowScan architecture: connectors collect per surface, analysis and correlation score findings, reconciliation compares them with the sanctioned inventory" width="95%">
</p>

```text
connectors ── live API (collect) or offline export (input) ──► records
records ── analyze() against YAML signature packs ──► findings with evidence
findings ── merge ─► correlate across surfaces ─► reconcile with inventory and trusted
            registries ─► classify autonomy ─► score risk ─► (opt-in) LLM triage
report ──── table · json · sarif · csv · markdown · html · cyclonedx · ocsf
JSON reports ── diff · merge (fleet) · dashboard · controls · inventory stubs
```

Most detection knowledge lives in YAML signature packs, and threat and control
references in YAML mapping catalogs, so recognizing a new product is usually a
data change rather than a code change.

Collection and analysis fail closed: an API error, a timeout, a refused page, an
unparseable manifest or a malformed export marks the scan incomplete (exit 3)
rather than producing a smaller report that looks clean. A gap the scanner can
bound, such as a handful of unreadable entries in a large tree, is instead
charged against a 2% coverage budget (at most 100 weighted entries per scan root;
vendored and test paths count a quarter). `--max-coverage-gap` sets the budget
and `strict_coverage` disables it. Bounded gaps are counted in the JSON report's
`stats[].coverage` whether or not they change the exit code; the first 50 are
listed under `stats[].coverage.details`, and `details_truncated` counts the rest.
The opt-in `--profile ci` of `shadowscan code` declares some gaps under test,
fixture, documentation, example and generated paths as counted omissions
instead. Only the opt-in LLM triage is advisory; its failures are warnings and it
never changes scores. See
[architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md)
for the pipeline, the package layout and the connector contract.

## Key capabilities

| Capability | Details |
|---|---|
| **38 connectors** across 9 surfaces | Code, Identity, Gateway, Low-code, SaaS, Cloud, Endpoint, Network, Runtime |
| **233 signatures / 1133 signals** | Orchestrators, protocols, coding agents, platforms, model providers, AI SaaS apps, permission policies |
| **Live and offline modes** | 28 of the 38 connectors collect from a live API or the local host. 35 replay JSON, YAML, CSV or log exports; the three code connectors read a checkout or a directory of clones instead. The other 10 are replay-only by design: Kubernetes and OpenShift manifest dumps, gateway logs and OTel traces, network logs, host, local-model, model-artifact and eBPF endpoint exports, and generic SaaS exports |
| **8 output formats** | `table` · `json` · `sarif` · `csv` · `markdown` · `html` · `cyclonedx` · `ocsf` |
| **Risk scoring** | Additive, explainable 0-100 score with per-factor breakdown |
| **Autonomy classification** | L0 (Chatbot) through L5 (Fully Autonomous) interval |
| **Inventory reconciliation** | Agent Cards, `agents.yaml` lists, CSV inventories |
| **Threat & control mappings** | OWASP ASI, OWASP LLM, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act, AIUC-1 |
| **Fleet operations** | Merge reports, dashboard, diff for drift detection, control evidence |
| **CI/CD integration** | GitHub Actions SARIF upload, deterministic exit codes, drift gating |
| **Fail-closed design** | Errors, timeouts and unbounded gaps produce exit 3 (incomplete), never a smaller clean report. Bounded gaps are budgeted (2% of entries by default, at most 100 per scan root) and always counted in the report |
| **Credential safety** | Known credential formats redacted before persistence; secret stores read for names and metadata only |

## Commands and exit codes

Run `shadowscan --help` or `shadowscan <command> --help` for the installed version.

| Task | Command |
|---|---|
| Local repository | `shadowscan code .` |
| Check local inputs | `shadowscan code . --preflight` |
| Only the changes since a base (Git 2.45+) | `shadowscan code . --diff-base origin/main` |
| Staged Git files (Git 2.45+) | `shadowscan code --quick` |
| GitHub repositories | `shadowscan run code.github --set 'repos=["OWNER/REPO"]'` |
| This workstation's AI clients | `shadowscan endpoint` |
| Gateway logs | `shadowscan gateway access.log litellm-spend.jsonl` |
| JWTs: human, service or agent | `shadowscan jwt --file tokens.txt --jwks-url https://login.example.com/.well-known/jwks.json` |
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

## Benchmarks

In the three October 2026 ShadowBench runs below, ShadowScan had the highest
headline score of the open-source tools tested, and in the two multi-surface runs
it was the only tool that covered every surface. The maintainer designed, ran and
scored all three; read the caveats under the charts before comparing tools. The
benchmarks were developed in this repository and have since moved, byte-for-byte,
to [Nexus ShadowBench](https://github.com/aisecnomad/Nexus-ShadowBench). Every
report link below opens a fixed ShadowBench commit, and none of these runs was
rerun or regraded in the move.

| Run | Inputs | ShadowScan | Next-best open-source tool, same metric |
|---|---|---|---|
| [Head-to-head](https://github.com/aisecnomad/Nexus-ShadowBench/blob/1ce0eee376585f85fbd0fec98235d556310e6277/tools/benchmark/results/REPORT.md) (tools pinned 2026-10-06) | 900 synthetic cases: repository, endpoint, network | Estate recall 0.90 (0.87–0.92) | Cisco AI BOM 0.49 (0.45–0.53) |
| [ShadowBench cases](https://github.com/aisecnomad/Nexus-ShadowBench/blob/1ce0eee376585f85fbd0fec98235d556310e6277/benchmarks/shadowbench/cases/results/2026-10-11/REPORT.md) (2026-10-11) | 346 cases, 738 entities, nine surfaces | Estate recall 0.839 | AI-Infra-Guard, AgentDiscover 0.035 |
| [Shadow AI discovery](https://github.com/aisecnomad/Nexus-ShadowBench/blob/1ce0eee376585f85fbd0fec98235d556310e6277/benchmarks/shadow-ai-discovery/results/2026-10-09/REPORT.md) (2026-10-09) | 87 public repositories, code surface | In-scope value F1 0.972 | NuGuard 0.750 |

Estate recall is the share of all labeled entities a tool found across every
surface in the run, so it charges each tool for the surfaces it does not cover.

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/84183af55768191b6a4044b424a2e8e57013763a/docs/assets/benchmarks-head-to-head.webp" alt="Head-to-head estate recall on 900 synthetic cases: ShadowScan 0.90, Cisco AI BOM 0.49, AgentSonar 0.33, agent-bom 0.29, Shadow AI Detector 0.28, AgentDiscover 0.23, Open Shadow AI 0.19, Snyk Agent Scan 0.18, AI-Detector 0.13, Cisco MCP Scanner 0.04, Claw-Hunter 0.04" width="95%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/84183af55768191b6a4044b424a2e8e57013763a/docs/assets/benchmarks-cross-tool.webp" alt="Left: ShadowBench cases estate recall, ShadowScan 0.839 against 0.035 or less for every other tool. Right: Shadow AI discovery value-level F1, ShadowScan 0.972, NuGuard 0.750, SafeDep vet 0.587, Trusera ai-bom 0.585, cdxgen 0.511" width="95%">
</p>

How to read these numbers:

* They are evidence about the listed inputs, **not** independent review and
  **not** measured field accuracy. The maintainer built every corpus and wrote or
  supervised every label, scorer and tool adapter.
* The head-to-head was pre-registered, with ShadowScan's results committed before
  any other tool ran. The cases run was re-scored after the run with its results
  in view.
* The discovery result is in-sample: the 0.972 F1 was measured after tuning on
  that corpus. An earlier archived run recorded
  [0.909](https://github.com/aisecnomad/Nexus-ShadowBench/blob/1ce0eee376585f85fbd0fec98235d556310e6277/benchmarks/shadow-ai-discovery/results/2026-10-08/REPORT.md)
  on a slightly different set of expected facts, so the two are not a controlled
  before-and-after comparison.
* Estate recall mostly measures coverage: compare tools on the in-scope columns in
  each report, not on these headline numbers. Several tools ran below full
  capability.
* ShadowScan still has gaps. It found 70% of AI developer home directories in the
  head-to-head, its specificity on decoys in the cases run was 63%, and it marked
  27 of its 326 scans in the cases run and 43 of 87 in the discovery run
  incomplete.
* Not every ShadowBench run favors it: in three
  [real-world repository runs](https://github.com/aisecnomad/Nexus-ShadowBench/blob/1ce0eee376585f85fbd0fec98235d556310e6277/benchmarks/README.md)
  from 2026-10-08 (34, 41 and 326 public repositories), other tools scored higher,
  partly because those runs count ShadowScan's incomplete scans as misses.

See [benchmark evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md#benchmarks)
for per-surface results and limits.

## Data handling and safety

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data, so treat them as confidential.
* Secret stores (AWS Secrets Manager and Systems Manager Parameter Store, Google Secret Manager, OCI Vault) are read for **names and metadata only**. The Azure collector reads App Service application settings to find credentials and redacts them before persistence; set `include_app_settings: false` to skip them.
* JWTs are never persisted; findings reference a truncated hash.
* Built-in collectors inspect provider resources using read operations. Scope the audit identity to the documented read permissions and review any enabled third-party plugin separately.
* ShadowScan sends no telemetry. It connects only to the sources a scan is configured to read and, if you enable the opt-in LLM triage, to the model endpoint you choose, which receives redacted finding summaries.

See [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md) and [docs/production.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md) for deployment behavior, migration and limits.

## Documentation

| Topic | Reference |
|---|---|
| Installation and first scan | [Installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md), [quick start](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md) |
| Options and configuration | [CLI reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md), [configuration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) |
| Examples, output and detection | [Product guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md), [connector reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors/reference.md) |
| Python integration | [API reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/api/index.md) |
| Benchmark protocols and limitations | [Benchmark evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/product-guide.md#benchmarks) |
| Production use and trust boundaries | [Deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md), [threat model](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/security/threat-model.md) |

These links open the documentation on `main`, which can describe changes made
after the version you installed. The documentation for an installed version is at
its release tag, `https://github.com/aisecnomad/Nexus-ShadowScan/tree/v<version>`;
`shadowscan --version` prints the version.

## Project status

* **Release state.** Alpha; the package classifier is `Development Status :: 3 - Alpha`.
  A version is published when it appears in the
  [PyPI release history](https://pypi.org/project/NexusShadowScan/#history) and as a
  [release tag](https://github.com/aisecnomad/Nexus-ShadowScan/tags); a version
  number in the source is not evidence of publication, and commits on `main` after
  a release tag are unreleased. Confirm a version's publication and artifact
  identity there before installing it. Publication does not establish independent
  review or deployment acceptance.
* **Single maintainer, AI-assisted development.** Apart from Dependabot updates, every commit up to this revision was written
  by a single maintainer or generated with an AI coding assistant (Claude, Codex, Grok, GitHub Copilot, Google Antigravity, Perplexity, Meta AI, etc.). The logs under
  [archive/reviews/](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/archive/reviews) are AI-assisted, not third-party reviews.
* **Recommendation.** Review the revision yourself or have it reviewed, then
  pin that full commit SHA as shown in
  [Deployment install](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).
  Review state cannot be established from a checkout; verify it with the
  commands in
  [merge gate and review status](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#merge-gate-and-review-status).
* **Name.** The repository was formerly `aisecnomad/Project-Nexus`; GitHub redirects the old links.

## Community and contributing

| I want to… | Start here |
|---|---|
| Ask a question or troubleshoot | [Support guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) |
| Report a bug or request a feature | [Issue forms](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new/choose) |
| Report a false positive or missed framework | [Detection quality report](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=detection_report.yml) |
| Make a first contribution | [Contributor guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md) |
| Report a vulnerability privately | [Security policy](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#reporting) |
| Understand decisions, review and release requirements | [Governance](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md), [Maintainers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/MAINTAINERS.md), [Roadmap](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/ROADMAP.md) |
| Understand participation standards | [Code of conduct](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CODE_OF_CONDUCT.md) |
| See what changed or cite the project | [Release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md), [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [Engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

Use synthetic, minimal examples in public reports. Scan results can contain
credentials, personal data, and sensitive inventory even after redaction.

## License

Apache-2.0. See [LICENSE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and [NOTICE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE).
