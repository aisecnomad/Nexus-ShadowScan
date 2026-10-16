<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/hero-banner.svg" alt="Nexus ShadowScan — open-source AI agent discovery" width="100%">
</p>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-ShadowScan"><img src="https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-ShadowScan/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.13-blue.svg" alt="Python 3.11-3.13"></a>
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

---

<details open>
<summary><h2>Table of Contents</h2></summary>

**Get Started**
- [Why ShadowScan](#why-shadowscan) · [How it works](#how-it-works) · [Key capabilities](#key-capabilities) · [Install](#install) · [Quick start](#quick-start)

**Reference**
- [Command reference](#command-reference) · [Python API](#python-api-reference) · [Output formats](#output-formats) · [Exit codes](#exit-codes)

**Configuration & Detection**
- [Configuration](#configuration) · [Detection matrix](#detection-matrix) · [Surfaces & connectors](#surfaces--connectors) · [Frameworks & products recognized](#frameworks--products-recognized)

**Results & Assessment**
- [Example output](#example-output) · [What a finding looks like](#what-a-finding-looks-like) · [Sanctioned inventory](#sanctioned-inventory) · [Benchmarks](#benchmarks)

**Extend & Operate**
- [Extending](#extending) · [Documentation](#documentation) · [Evidence and assurance limits](#evidence-and-assurance-limits)

**Project**
- [Project status](#project-status) · [Community and contributing](#community-and-contributing) · [Safety and security notes](#safety-and-security-notes) · [License](#license)

</details>

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
a code change. Collection and analysis fail closed: an API error, a timeout, a
limit or a malformed export marks the scan incomplete (exit 3) rather than
producing a smaller report that looks clean. Only the opt-in LLM triage is
advisory; its failures are warnings and it never changes scores. See
[architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md)
for the pipeline, the package layout and the connector contract.

## Key capabilities

| Capability | Details |
|---|---|
| **38 connectors** across 9 surfaces | Code, Identity, Gateway, Low-code, SaaS, Cloud, Endpoint, Network, Runtime |
| **233 signatures / 1133 signals** | Orchestrators, protocols, coding agents, platforms, model providers, AI SaaS apps, permission policies |
| **Live and offline modes** | Scan live APIs with credentials or replay offline JSON/CSV/log exports |
| **8 output formats** | `table` · `json` · `sarif` · `csv` · `markdown` · `html` · `cyclonedx` · `ocsf` |
| **Risk scoring** | Additive, explainable 0-100 score with per-factor breakdown |
| **Autonomy classification** | L0 (Chatbot) through L5 (Fully Autonomous) interval |
| **Inventory reconciliation** | Agent Cards, `agents.yaml` lists, CSV inventories |
| **Threat & control mappings** | OWASP ASI, OWASP LLM, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act, AIUC-1 |
| **Fleet operations** | Merge reports, dashboard, diff for drift detection, control evidence |
| **CI/CD integration** | GitHub Actions SARIF upload, deterministic exit codes, drift gating |
| **Fail-closed design** | Errors, timeouts and limits produce exit 3 (incomplete), never a smaller clean report |
| **Credential safety** | Known credential formats redacted before persistence; secret stores read for names only |

---

## Install

```bash
pip install NexusShadowScan                  # or: pipx install NexusShadowScan
pip install "NexusShadowScan[cloud]"         # adds AWS, GCP, Azure, and OCI SDKs
shadowscan --help
```

> **Requirements:** Python 3.11, 3.12 or 3.13.
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
ShadowScan checkout itself reports an incomplete scan (exit 3), because some
redaction tests and benchmark files deliberately exceed the scanner's limits
and it fails closed rather than skip them; in a checkout,
`shadowscan code tests/fixtures/sample_repo --inventory agent-card.yaml`
completes in seconds.

See the [quick start guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md)
for walkthroughs of each surface and the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) for all options.

---

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

Every scan command accepts `-f/--format`, `-o/--output`, `-i/--inventory`, `-s/--signatures`, `--fail-on`, `--min-confidence`, `--dump-records`, `--incremental`, `--job-deadline-seconds`, and security boundary flags.
Run `shadowscan <command> --help` for full option details.

### Output formats

`table` (default) · `json` · `sarif` · `csv` · `markdown` · `html` · `cyclonedx` (AI-BOM) · `ocsf` (SIEM)

### Exit codes

| Exit | Meaning |
|---|---|
| **0** | Scan completed and passed |
| **1** | Invalid option, path, configuration, or setup/output error |
| **2** | Reached `--fail-on` threshold; `diff` with `--fail-on-new` / `--fail-on-drift` |
| **3** | Incomplete scan (API error, timeout, limit, malformed export); `diff` when reports are not comparable |

Gate CI on any non-zero exit. Exit 0 from a complete static scan does not
prove no agent runs; see
[scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md).

---

## Python API reference

The CLI is built on the same Python API. The JSON report (`--format json`) is
the stable contract; treat the Python objects as unstable between releases
until 1.0 and pin a reviewed commit.

```python
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine

cfg = ScanConfig(
    connectors=[ConnectorSpec("code.filesystem", {"paths": ["./my-repo"]})],
    inventory=["./inventory"],
)
result = Engine(cfg).run()

if not result.complete:
    raise SystemExit(3)  # fail closed: an incomplete scan is never a clean one

for finding in result.findings:
    print(f"[{finding.risk.level.value}] {finding.title}  shadow={finding.shadow}")
```

`ScanConfig.from_yaml("shadowscan.yaml")` reads the same YAML file as `shadowscan scan -c`.
See the full [API reference](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/docs/api) for
engine, models, config, risk, autonomy, correlation, comparison, registry, signatures, reporters, and the HTTP client.

---

## Configuration

```yaml
# shadowscan.yaml — minimal example
inventory: [./inventory]
connectors:
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    token: ${SLACK_TOKEN}
  - name: cloud.aws
    regions: [us-east-1, eu-west-1]
```

> **Security:** Keep secrets in the environment (`${VAR}`), never in the file.
> The scanner rejects a configuration that mixes a live code connector with
> credentialed tenant connectors unless `options.allow_credential_mixing` is set,
> and cloud instance-metadata credentials need `options.allow_instance_credentials`.
> Run repository scans separately from live tenant collection.

<details>
<summary><strong>Full configuration options</strong></summary>

```yaml
# shadowscan.yaml — full reference
inventory: [./inventory]              # Agent Cards, agents.yaml, or CSV
signatures: [./custom-signatures]     # optional extra or overriding packs
options:
  min_confidence: 0.3                 # finding threshold (0.0-1.0)
  fail_on: high                       # exit 2 if any finding reaches this level
  dump_records: ./exports             # sanitized records for offline re-runs
  connector_timeout_seconds: 120      # cooperative deadline per connector
  job_deadline_seconds: 600           # whole-process deadline
  allow_private_origin: false         # permit non-global IP addresses
  allow_instance_credentials: false   # permit cloud instance-metadata credentials
  allow_credential_mixing: false      # permit repo + live tenant in one scan
  allow_signature_override: false     # permit custom sigs to replace built-in IDs
  plugins: []                         # exact-name allowlist for third-party connectors
  plugin_execution: process           # or thread
  risk_basis: combined                # or danger (excludes governance factors)
  incremental: false                  # content-addressed result caching
  state_dir: .shadowscan-state       # private incremental state directory
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
  # ... see docs/connectors.md for all connector keys
```

</details>

`shadowscan connectors` lists each connector's configuration keys and required
extras; `shadowscan connectors --json` also lists offline export formats. See the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) for all options and the
[connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) for credential scopes and offline formats.

---

## Example output

Abridged offline demo (`--max-rows 5` shows the five highest-risk rows):

```
$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 5

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 132 findings  •  128 shadow (inventory: 4 registered agents)               │
│ critical 16  high 62  medium 54  •  cloud 30 identity 19 endpoint 18 …     │
╰────────────────────────────────────────────────────────────────────────────╯
 CRITICAL 100  SHADOW  code      mcp-server   MCP configuration: .mcp.json
 CRITICAL 100  SHADOW  saas      bot-app      GitHub App installed: claude
 CRITICAL  98  SHADOW  code      agent-config Claude Code configured in repository root
 CRITICAL  91  SHADOW  endpoint  agent-config OpenClaw configured on dev-laptop-07 (~dana)
 CRITICAL  90  SHADOW  code      secret       LLM provider credential in services/research-agent/app/config.py
```

SARIF output (`--format sarif`) integrates with GitHub Code Scanning; results carry heuristic risk levels, not CVSS scores.
See [severity](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md).

---

## Detection matrix

<!-- BEGIN detection-matrix: generated by `python -m tools.readme_matrix`; do not edit by hand -->

### Agent frameworks and SDKs

A check means ShadowScan recognizes the framework's packages in that ecosystem's
manifests and lockfiles or its imports in that language. *Agent evidence* says what
makes a finding an agent: *any use* of the framework, or *agent constructs* in code,
such as an agent executor or tool-calling agent, rather than plain LLM calls.

| Framework | Python | JS/TS | JVM | .NET | Go | Rust | Agent evidence |
|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| LangChain | ✓ | ✓ |  |  |  |  | agent constructs |
| LangGraph | ✓ | ✓ |  |  |  |  | any use |
| CrewAI | ✓ |  |  |  |  |  | any use |
| AutoGen / AG2 | ✓ |  |  | ✓ |  |  | any use |
| Microsoft Agent Framework | ✓ |  |  | ✓ |  |  | any use |
| Semantic Kernel | ✓ |  | ✓ | ✓ |  |  | agent constructs |
| OpenAI Agents SDK | ✓ | ✓ |  |  |  |  | any use |
| Claude Agent SDK | ✓ | ✓ |  |  |  |  | any use |
| Google Agent Development Kit (ADK) | ✓ | ✓ | ✓ |  | ✓ |  | any use |
| AWS Strands Agents | ✓ |  |  |  |  |  | any use |
| LlamaIndex | ✓ | ✓ |  |  |  |  | agent constructs |
| Pydantic AI | ✓ |  |  |  |  |  | any use |
| Hugging Face smolagents | ✓ |  |  |  |  |  | any use |
| Mastra |  | ✓ |  |  |  |  | any use |
| Vercel AI SDK |  | ✓ |  |  |  |  | agent constructs |
| LangChain4j |  |  | ✓ |  |  |  | agent constructs |
| Spring AI |  |  | ✓ |  |  |  | agent constructs |
| LangChainGo |  |  |  |  | ✓ |  | agent constructs |

The grid shows 18 of 79 framework signatures; `shadowscan signatures list --category framework` lists all of them.

### MCP servers and clients

Recognizes MCP client configs (16 file patterns in repos, 21 clients on workstations), server packages across 6 ecosystems, container image patterns, 14+ remote MCP hosts, and MCP environment variables.
`shadowscan signatures show protocol.mcp` prints the full signal list.

### Other connectors

22 connectors cover identity (Okta, Entra, Google Workspace, Auth0, JWT), gateway (logs, OpenTelemetry), low-code (Power Platform, Salesforce, ServiceNow, n8n, Make, Zapier, Workato), SaaS (Slack, Teams, GitHub Apps, Atlassian, Notion, Zoom, generic), and network (DNS/TLS/flow logs). All support offline JSON/CSV exports.
See the [connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) for credential scopes and offline formats.

<!-- END detection-matrix -->

---

## Benchmarks

Author-written regression benchmarks (not independent review or production precision/recall):

| Track | F1 | Details |
|---|---|---|
| [ShadowBench estate](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/estate/results/2026-10-11/REPORT.md) (9 surfaces, 137 entities) | 93.3% | 83/87 positives found, 8/50 controls flagged |
| [Shadow AI discovery](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadow-ai-discovery/results/2026-10-09/REPORT.md) (code, 87 repos) | 97.2% | 65/65 positives flagged, 0/22 controls flagged |

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/benchmarks-cross-tool.webp" alt="Cross-tool benchmark comparison" width="95%">
</p>

See the [benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md) for methodology, limits, cross-tool comparisons, and reproduction steps.

---

## Surfaces & connectors

ShadowScan ships **38 connectors** across the nine surfaces below.

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

Connectors support **live** API collection, **offline** JSON/CSV/log exports,
or both; see the [connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) for supported modes and provider scope.
The offline inventories (`endpoint.host`, `endpoint.mcp`, `endpoint.ollama`,
`endpoint.models`, `endpoint.ebpf`, `gateway.otel`, `cloud.kubernetes`,
`cloud.openshift`) analyze exports and never probe endpoints or a Kubernetes
API; the one opt-in exception is `endpoint.mcp` fetching the A2A Agent Cards
listed in `agent_card_urls`. Without an `input`, `endpoint.inventory` reads a
fixed list of user-scope client locations (model files are listed by name,
never parsed) and `runtime.processes` reads `/proc` on Linux.

## What a finding looks like

```json
{
  "id": "ss-3f9c1e2a7b4d8c10",
  "surface": "cloud", "connector": "cloud.aws", "kind": "agent",
  "title": "Bedrock AgentCore runtime: strands_support_agent",
  "resource": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt1",
  "account": "123456789012", "region": "us-east-1", "owner": null,
  "frameworks": ["cloud.aws-bedrock-agents"], "model_providers": ["provider.openai"],
  "capabilities": ["tool-use"], "tags": ["plaintext-credential", "secret-in-env"],
  "confidence": 1.0, "likelihood": "strong",
  "shadow": true, "registry_match": null,
  "risk": {"score": 90, "level": "critical", "factors": [
      {"id": "shadow", "description": "not present in the sanctioned agent inventory", "weight": 25},
      {"id": "tag:plaintext-credential", "description": "plaintext credential in environment/configuration", "weight": 25},
      {"id": "no-owner", "description": "no identifiable owner", "weight": 10}, "..."]},
  "evidence": [
      {"signal": "aws:agentcore-runtime", "description": "AgentCore runtime 'strands_support_agent' (READY) role arn:aws:iam::…", "weight": 0.97},
      {"signal": "secret:provider.openai", "description": "Plaintext OpenAI API key in environment variable OPENAI_API_KEY: credential:hmac-sha256:…", "weight": 0.6}],
  "metadata": {"status": "READY", "protocol": "HTTP", "network": "PUBLIC", "related": ["ss-…"],
      "threats": ["maestro-2025:L3", "mitre-atlas-2026.09:AML.T0055", "owasp-asi-2026:ASI03", "owasp-llm-2026:LLM02"],
      "controls": ["aiuc-1-2026q2:B", "aiuc-1-2026q2:E", "eu-ai-act-2024:Art.15", "..."]}
}
```

For field definitions (confidence, risk, shadow, autonomy, threats, controls) see the
[risk scoring](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/risk.md),
[autonomy tiers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/autonomy.md) and
[mappings](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/mappings.md) documentation.

## Frameworks & products recognized

233 signatures / 1133 signals, YAML-defined with explicit opt-in overrides:

<details>
<summary><strong>Full framework and product list</strong></summary>

* **Orchestrators** – LangChain, LangGraph, Deep Agents, LlamaIndex, CrewAI, Google ADK, AWS Strands Agents, Microsoft Agent Framework, Semantic Kernel, Microsoft.Extensions.AI, AutoGen/AG2, Hugging Face smolagents and Transformers Agents, OpenAI Agents SDK, OpenAI Swarm, Agency Swarm, Claude Agent SDK, Pydantic AI, Vercel AI SDK, Mastra, Haystack, DSPy, Instructor, Embedchain, Agno, Letta, MetaGPT, CAMEL, Griptape, Composio, Langroid, AgentScope, Swarms, AutoGPT, BabyAGI, BeeAI, Atomic Agents, Julep, Marvin, Mirascope, Qwen-Agent, NVIDIA NeMo Agent Toolkit, Dapr Agents, PraisonAI, SWE-agent, GPT Engineer, Open Interpreter, Chainlit, Prompt flow, Guardrails AI / NeMo Guardrails / LLM Guard, LangChain4j, Spring AI, Koog, Rig, LangChainGo, Genkit, Eino, M365 Agents SDK, Bot Framework, Teams AI, Cloudflare Agents, Inngest AgentKit, VoltAgent, CopilotKit/AG-UI, Rasa, Botpress, Browser Use, Stagehand, OpenHands, Nova Act, Anthropic computer use
* **Protocols** – MCP (all client config locations, servers, registries, remote MCP hosts), A2A agent cards, ACP, tool/function-calling request shapes, ChatGPT plugin/GPT Action manifests
* **Coding agents** – Claude Code, GitHub Copilot coding agent, Devin, Cursor, Windsurf, Cline, Roo, OpenAI Codex, Gemini CLI/Jules, Amazon Q/Kiro, Goose, Aider, Continue, Cody/Amp, Junie, AGENTS.md, PR review bots (CodeRabbit, Sweep, Ellipsis, Greptile, Qodo…)
* **Platforms/gateways** – LiteLLM, Portkey, Kong AI Gateway, Helicone, MLflow AI Gateway, OpenAI AgentKit, Dify, Flowise, Langflow, n8n, Make, Zapier, Workato, Copilot Studio, Power Platform AI connectors, M365 declarative agents, Agentforce, Now Assist, IBM watsonx Orchestrate, Retool, Rivet, Browserbase, Open WebUI/LibreChat/AnythingLLM, Coze/Relevance/Lindy/Vellum…
* **Model providers** – OpenAI, Anthropic, Gemini API, Vertex AI, Bedrock, Azure OpenAI, Mistral, Cohere, Groq, Together, Fireworks, OpenRouter, Ollama, vLLM, SGLang, llama.cpp, LM Studio, LocalAI, Llama Stack, Meta Llama API, Hugging Face, xAI, DeepSeek, Alibaba DashScope/Qwen, Moonshot/Kimi, AI21, Perplexity, Voyage AI, Replicate, Cerebras, SambaNova, NVIDIA NIM, OCI Generative AI, watsonx, Databricks, Cloudflare Workers AI, Snowflake Cortex (deps, imports, endpoints, env vars, user agents, model IDs, **key formats**)
* **Observability/memory/sandboxes** – LangSmith, Langfuse, Phoenix, AgentOps, Traceloop, Weave, Braintrust…, Mem0, Zep, vector stores, E2B, Daytona, web search/scrape tool providers
* **AI SaaS as OAuth apps** – ChatGPT, Claude, Gemini, Copilot, Perplexity, Mistral Le Chat, DeepSeek, Qwen, Kimi, Grok, Poe, Character.ai, Glean, meeting note-takers (Otter, Fireflies, Read.ai, Fathom, tl;dv, Gong…), writing/coding/automation/research/media products, browser AI extensions
* **Permission policies** – privileged, data-access and LLM-access scope classes across Graph, Google, Okta, Slack, GitHub, GitLab, Salesforce, Atlassian, Zoom, Notion, HubSpot, AWS IAM, Azure RBAC, GCP IAM, OCI

</details>

`shadowscan signatures list` shows everything; `shadowscan signatures test <value>`
tells you what a package, host, user agent, model ID, scope, or file path maps to.

## Sanctioned inventory

Drop [Agent Cards](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/agent-card.yaml) in a directory and point `inventory:` at it.
Simple `agents.yaml` lists and CSV work too. `shadowscan inventory stubs`
generates card skeletons from shadow findings. See
[docs/inventory.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/inventory.md).

## Extending

* **Signatures** are YAML: add a pack directory with `--signatures` or
  `signatures:`. Replacing a built-in signature requires explicit opt-in
  (`allow_signature_override`). See
  [docs/signatures.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/signatures.md).
* **Connectors** implement `collect()` (live) and `analyze()` (records to
  findings) and register through the `shadowscan.connectors` entry-point group.
  A third-party connector runs only when an exact-name `options.plugins`
  allowlist entry (or `--allow-plugin`) names it. An allowlisted plugin runs
  with the scanner's privileges: by default (`plugin_execution: process`) it runs
  in a worker the scanner can stop at its deadline, but that is not a sandbox. See
  [writing a connector](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md#writing-a-connector)
  and [third-party plugin execution](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md#third-party-plugin-execution).

## Documentation

The [`docs/`](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/docs)
directory of the revision you run is the source of truth.

| Topic | Pages |
|---|---|
| Getting started | [Installation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md), [quick start](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md), [configuration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) |
| How it works | [Architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md), [scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md), [signatures](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/signatures.md), [design decisions (ADRs)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/adrs/index.md) |
| Connectors | [Connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md), [configuration key reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors/reference.md) |
| Assessment | [Inventory](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/inventory.md), [risk scoring](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/risk.md), [autonomy tiers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/autonomy.md), [threat and control mappings](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/mappings.md), [severity](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md) |
| Operations | [CI integration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ci.md), [scheduled drift](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/drift.md), [fleet dashboard](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/dashboard.md), [control evidence report](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/controls.md), [AI-BOM](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ai-bom.md), [OCSF](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ocsf.md), [LLM triage](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/llm-triage.md) |
| Deployment and assurance | [Production deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md), [evaluation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md), [tenant canaries](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/canaries.md), [external reviewer packet](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/reviewer-packet.md) |
| Python API | [API reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/api/index.md) — engine, models, config, risk, autonomy, correlation, merge, comparison, registry, signatures, reporters, HTTP client, redaction |

## Development

```bash
python -m venv .venv && source .venv/bin/activate
make install          # hash-locked runtime, cloud, dev and docs toolchain
make check            # lint, format, types, signatures, mappings, secrets, audit, coverage, connector floor, evaluation
```

Run `make help` or see the [Makefile](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/Makefile) for the full target list (install, lint, format, typecheck, test, coverage-gate, signatures, mappings, secrets, audit, evaluate, docs, build, docker, clean).

See [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#getting-started)
to get started and its [repository map](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#find-your-way-around)
for where the code, tests, docs, tooling and benchmarks live.

## Evidence and assurance limits

- **Evaluation corpora** are author-written regression cases, not independent field-precision estimates. See [evaluation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md).
- **Benchmarks against other tools** use inputs and labels the same maintainer wrote. They show behavior on those inputs, not field accuracy, and none is independent. See the [benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md).
- **Assurance results** use a frozen corpus of 42 public files labeled by two AI reviewers, not independent human ground truth; only the baseline run is out of sample.
- **Canaries** validate named tenant controls when credentials are supplied; offline replay does not establish live acceptance. See [canaries](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/canaries.md).
- **The acceptance verifier** validates supplied holdout and tenant evidence but cannot authenticate reviewer independence or manufacture tenant acceptance. See the [verifier](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/acceptance/README.md).
- Review [rollout acceptance](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#rollout-acceptance) before using a risk threshold as a production gate.

## Project status

* **Release state.** Version `0.1.2` is published to PyPI as `NexusShadowScan`
  and tagged `v0.1.2`, as an alpha pre-release. The package classifier is `Development Status :: 3 - Alpha`.
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
| See what changed or cite the project | [Release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md), [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

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
