<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/hero-banner.svg" alt="Nexus ShadowScan — open-source AI agent discovery" width="100%">
</p>

# Nexus ShadowScan

[![CI](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml/badge.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml/badge.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-ShadowScan/badge)](https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-ShadowScan)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE)
[![Python 3.11–3.13](https://img.shields.io/badge/python-3.11%E2%80%933.13-blue.svg)](https://www.python.org/downloads/)
[![Coverage ≥80%](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates)
[![Docs](https://img.shields.io/badge/docs-source-blue.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/docs)
[![PyPI: NexusShadowScan](https://img.shields.io/pypi/v/NexusShadowScan.svg)](https://pypi.org/project/NexusShadowScan/)

**Discover shadow AI agents across your organization and reconcile them against your approved inventory.**

It inspects nine surfaces: code repositories, identity providers, LLM gateway logs,
low-code platforms, SaaS apps, cloud accounts, endpoints (developer workstations and
host/runtime inventories), network logs, and running processes.

| GitHub repository | PyPI distribution | Command |
|---|---|---|
| [`aisecnomad/Nexus-ShadowScan`](https://github.com/aisecnomad/Nexus-ShadowScan) | [`NexusShadowScan`](https://pypi.org/project/NexusShadowScan/) | `shadowscan` |

## Install

```bash
pip install NexusShadowScan          # or: pipx install NexusShadowScan
shadowscan --help
```

For cloud connectors (AWS, GCP, Azure, OCI): `pip install "NexusShadowScan[cloud]"`.
Python 3.11–3.13 required. For production deployment with hash-locked dependencies,
see the [installation guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md).

## Quick start

```bash
# Scan a local repository — no credentials needed
shadowscan code .

# Try every connector offline with bundled fixtures (36 of 38 connectors ship fixtures; needs a checkout)
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html

# Real estate: live connectors with secrets from the environment
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif
```

See the [quick start guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/quickstart.md)
for walkthroughs of each surface and the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) for all options.

## Command reference

| Command | What it does |
|---|---|
| `shadowscan code <path>` | Scan a repository or directory for AI agent evidence |
| `shadowscan code <path> --diff-base origin/main` | Scan only committed changes (PR scope, Git 2.45+) |
| `shadowscan scan -c <config.yaml>` | Run a multi-connector scan from a config file |
| `shadowscan run <connector> [--set key=val]` | Run one connector ad-hoc |
| `shadowscan run <connector> --input <export>` | Re-analyze an offline export |
| `shadowscan endpoint` | Scan local AI client locations (MCP configs, coding-agent settings) |
| `shadowscan gateway <logs...>` | Analyze AI gateway / provider log files |
| `shadowscan jwt --file <token>` | Classify a JWT as human, service or agent identity |
| `shadowscan merge <reports...>` | Combine multiple JSON reports into one fleet report |
| `shadowscan dashboard <report.json>` | Generate a static fleet dashboard (HTML) |
| `shadowscan diff <old.json> <new.json>` | Compare reports: new findings, drift, resolution |
| `shadowscan inventory stubs <report.json>` | Generate Agent Card skeletons for shadow findings |
| `shadowscan controls <report.json>` | Map findings to NIST AI RMF / ISO 42001 / EU AI Act / AIUC-1 controls |
| `shadowscan signatures list` | List all recognized signatures |
| `shadowscan signatures test <value>` | Test what a package, host, model ID, etc. maps to |
| `shadowscan connectors` | List connectors with configuration keys and required extras |

**Output formats:** `--format table` (default), `json`, `sarif`, `csv`, `markdown`, `html`, `cyclonedx`, `ocsf`

**Exit codes:**

| Exit | Meaning |
|---|---|
| **0** | Scan completed and passed |
| **1** | Invalid option, configuration or setup error |
| **2** | Scan completed but reached `--fail-on` threshold |
| **3** | Scan incomplete (API error, timeout, denied access) |

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

The same scan as SARIF for GitHub code scanning (`--format sarif`), first result
abridged:

```json
{
  "ruleId": "shadowscan/mcp-server/protocol.mcp",
  "level": "warning",
  "message": {
    "text": "MCP configuration: .mcp.json — risk critical (100), confidence 1.00 — SHADOW (not in inventory). Risk factors: mcp-server finding; not present in the sanctioned agent inventory; calls tools / functions; …"
  },
  "partialFingerprints": {"shadowscan/finding": "ss-c6e27e38faabb2a6"},
  "properties": {
    "surface": "code",
    "kind": "mcp-server",
    "shadow": true,
    "risk_level": "critical",
    "risk_score": 100,
    "confidence": 0.999,
    "frameworks": ["protocol.mcp", "platform.zapier"],
    "capabilities": ["tool-use", "saas-actions", "code-exec"],
    "tags": ["inline-secrets", "mcp-unpinned-package"],
    "threats": ["owasp-asi-2026:ASI02", "owasp-llm-2026:LLM03", "mitre-atlas-2026.09:AML.T0050"]
  },
  "locations": [
    {"physicalLocation": {"artifactLocation": {"uri": ".mcp.json", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}}}
  ]
}
```

SARIF results are warnings or notes carrying the heuristic risk level, never a
CVSS score; see [severity](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md).

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

| Evidence | Recognized |
|---|---|
| Client configuration in a repository | `.mcp.json`, `mcp.json`, `mcp-config.json`, `mcp_config.json`, `mcp-servers.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `.roo/mcp.json`, `.windsurf/mcp_config.json`, `cline_mcp_settings.json`, `.kiro/settings/mcp.json`, `.amazonq/mcp.json`, `.codeium/windsurf/mcp_config.json`, `smithery.yaml`, `.well-known/mcp.json` |
| Client configuration on a workstation (`endpoint.inventory`) | Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Roo Code, Gemini CLI, Codex CLI, Kiro, Amazon Q, GitHub Copilot CLI, Zed, Continue, Goose, opencode, `~/.mcp.json`, LM Studio, Aider, OpenClaw |
| Package dependencies | PyPI `mcp`, `fastmcp`, `mcp-server`, `langchain-mcp-adapters`, `mcp-agent`, `mcpadapt`, `fastapi-mcp`, `mcp-use`, `mcp-proxy`, `mcp-server-*`, `mcp-*`; npm `@modelcontextprotocol/sdk`, `@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-github`, `@modelcontextprotocol/server-postgres`, `@modelcontextprotocol/server-slack`, `@modelcontextprotocol/server-everything`, `@modelcontextprotocol/inspector`, `fastmcp`, `mcp-framework`, `@mcp-ui/server`, `@smithery/sdk`, `mcp-remote`, `@modelcontextprotocol/*`, `mcp-server-*`; Go `github.com/mark3labs/mcp-go`, `github.com/modelcontextprotocol/go-sdk`, `github.com/metoro-io/mcp-golang`, `github.com/mcp-go/mcp-go`; Cargo `rmcp`, `mcp-sdk`, `rust-mcp-sdk`, `mcp-core`; Maven `io.modelcontextprotocol.sdk:mcp`, `io.modelcontextprotocol.sdk:mcp-spring-webmvc`, `io.modelcontextprotocol.sdk:mcp-spring-webflux`, `org.springframework.ai:spring-ai-starter-mcp-server`, `org.springframework.ai:spring-ai-starter-mcp-client`, `org.springframework.ai:spring-ai-mcp`, `dev.langchain4j:langchain4j-mcp`, `io.modelcontextprotocol*`, `org.springframework.ai:spring-ai-starter-mcp*`, `org.springframework.ai:spring-ai-mcp*`; NuGet `ModelContextProtocol`, `ModelContextProtocol.AspNetCore`, `ModelContextProtocol.Core`, `ModelContextProtocol*` |
| Reference servers (npm) | `@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-github`, `@modelcontextprotocol/server-postgres`, `@modelcontextprotocol/server-slack`, `@modelcontextprotocol/server-everything` |
| Server image patterns (regular expressions) | `mcp/[a-z0-9-]+`, `ghcr\.io/github/github-mcp-server`, `modelcontextprotocol/`, `mcp-server` |
| Remote MCP hosts | `server.smithery.ai`, `registry.smithery.ai`, `mcp.zapier.com`, `mcp.composio.dev`, `api.githubcopilot.com`, `mcp.notion.com`, `mcp.linear.app`, `mcp.atlassian.com`, `mcp.stripe.com`, `mcp.paypal.com`, `mcp.sentry.dev`, `mcp.cloudflare.com`, `remote.mcpservers.org`, and hosts that match a regular expression in the `protocol.mcp` signature |
| Environment variables | `MCP_SERVER_URL`, `MCP_SERVER_PORT`, `MCP_TRANSPORT`, `MCP_API_KEY`, `FASTMCP_PORT`, `FASTMCP_HOST`, `SMITHERY_API_KEY` |

Gateway logs add MCP endpoint calls (`/mcp`, and `/sse` or `/messages` on a known MCP
host), and `runtime.processes` adds MCP servers seen running.

### Identity, gateway, low-code, SaaS and network connectors

| Surface | Connector | Discovers | Offline input |
|---|---|---|---|
| Identity | `identity.auth0` | Auth0 applications and machine-to-machine client grants. | JSON export of clients / client-grants |
| Identity | `identity.entra` | Entra ID service principals, OAuth consent grants, app-only permissions, app registrations, Agent ID agent identities and Microsoft Agent 365 packages via Microsoft Graph. | JSON export of Graph objects |
| Identity | `identity.google-workspace` | OAuth apps authorised by Google Workspace users (Admin SDK tokens), aggregated per client. | JSON export of token objects |
| Identity | `identity.jwt` | Classify JWTs as human, service or agent (delegated) identities and assess their privileges. | file with one token per line or JSON list / objects with `token` |
| Identity | `identity.okta` | Okta applications, OAuth service apps, admin/user consent grants. | JSON export of /api/v1/apps (with optional \_grants/\_tokens) |
| Gateway | `gateway.logs` | Reconstruct LLM callers (API keys, principals, services, user agents) from AI gateway / provider / proxy logs. | log file or directory (JSONL / JSON / CSV / nginx-envoy text) |
| Gateway | `gateway.otel` | Aggregate OpenTelemetry GenAI span exports without retaining prompt content. | OTLP JSON / JSONL span export |
| Low-code | `lowcode.make` | Make (Integromat) scenarios with AI modules and Make AI Agents. | scenarios JSON (with blueprint) / ai-agents JSON / blueprint files |
| Low-code | `lowcode.n8n` | n8n workflows using AI Agent / LLM / MCP nodes. | workflow list JSON or directory of exported workflows |
| Low-code | `lowcode.power-platform` | Copilot Studio agents, Power Automate flows and Power Apps that use AI connectors. | JSON export of environments / flows / apps / bots / botcomponents |
| Low-code | `lowcode.salesforce` | Agentforce agents, Einstein bots, prompt templates, AI flows, connected apps and user OAuth tokens. | JSON export of SOQL / Tooling query results |
| Low-code | `lowcode.servicenow` | Now Assist AI agents, tools, triggers, AI flows and OAuth application registries. | JSON export of table records |
| Low-code | `lowcode.workato` | Workato recipes using GenAI / LLM connectors and agentic recipes. | /api/recipes JSON |
| Low-code | `lowcode.zapier` | Zaps with AI steps (ChatGPT, Claude, Gemini, AI by Zapier) and Zapier Agents from account exports. | Zapier for Companies CSV/JSON export of Zaps or Agents |
| SaaS | `saas.atlassian` | Marketplace / Forge apps installed on Jira & Confluence Cloud (AI assistants, Rovo agents, automation bots). | UPM plugins JSON |
| SaaS | `saas.generic` | Offline app-inventory export from any SaaS admin console or CASB (column mapping via `fields`). | CSV / JSON export (required) |
| SaaS | `saas.github-apps` | GitHub Apps installed on an organisation (AI reviewers, coding agents), Copilot seats and approved fine-grained PATs. | installations JSON |
| SaaS | `saas.microsoft-teams` | Teams apps (custom + store) with bots, message extensions and Copilot agents, plus their installations. | JSON export of teamsApps / installedApps |
| SaaS | `saas.notion` | Notion integrations (bot users) connected to the workspace. | /v1/users JSON |
| SaaS | `saas.slack` | Slack apps, bot users, approved/restricted apps and install logs. | JSON export of users / apps / integration logs |
| SaaS | `saas.zoom` | Zoom Marketplace approved and account-created apps (not a per-user installation inventory). | marketplace apps JSON |
| Network | `network.logs` | AI services contacted per client address, from DNS, TLS SNI and flow logs (Zeek, Route 53 Resolver, VPC Flow Logs, generic exports). | log file or directory: Zeek dns/ssl/conn logs (TSV or JSON), Route 53 Resolver query logs, VPC Flow Logs or generic JSON/CSV DNS and SNI records |

Identity coverage is each provider's application, consent-grant and token inventory,
plus JWTs you supply; ShadowScan does not parse IdP sign-in or audit logs.
`gateway.logs` auto-detects these log schemas: `access-log`, `anthropic-usage`, `azure-openai`, `bedrock`, `cloudflare`, `generic`, `helicone`, `kong`, `langfuse`, `litellm`, `openai-usage`, `portkey`, `vertex`.
This table lists 22 of the 38 connectors; the code, cloud,
endpoint and runtime connectors are in [Surfaces & connectors](#surfaces--connectors).

<!-- END detection-matrix -->

## Benchmarks

Offline results from this repository's own benchmarks. The maintainer wrote
ShadowScan, both corpora, their labels and the harnesses, so these numbers are
regression evidence about the listed inputs. They are **not** independent review
and **not** measured production precision or recall.

| Track (run, version) | Inputs | ShadowScan result | Limits |
|---|---|---|---|
| [ShadowBench estate, nine surfaces](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/estate/results/2026-10-11/REPORT.md) (2026-10-11, 0.1.2) | 137 authored vendor-format entities for one fictional estate: 87 positive, 27 control, 23 near-miss | Entity precision / recall / F1 91.2% / 95.4% / 93.3%; 83 of 87 positives found; 8 of 50 controls and near-misses flagged | Authored artifacts; frozen after one label-completeness pass in which every runnable tool ran once (it added one secondary anchor and one tolerated pair and changed no label); later ShadowScan runs on it are in-sample (below) |
| [Shadow AI discovery, code surface](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadow-ai-discovery/results/2026-10-09/REPORT.md) (2026-10-09, 0.1.2+7bdea5300551) | 87 public repositories pinned by SHA: 65 positive, 10 control, 12 near-miss; 839 expected facts | Fact precision / recall / F1 99.8% / 94.8% / 97.2%; 65 of 65 positive repositories flagged; 0 of 22 controls and near-misses flagged (4 of those 22 runs incomplete) | 43 of 87 runs were incomplete (exit 3): fact counts are a lower bound, and an incomplete clean run is not a clean result |

Each report also runs other open-source tools on their declared scope, which is
narrower than nine surfaces; compare their in-scope columns in the report, not
these headline numbers. After the 2026-10-11 estate run, ShadowScan's
detection rules were changed with that run's errors in view (ambiguous Gemini
names, Notion bots, gateway `/api/chat` and `/generate` routes, Kubernetes
serving-engine images, n8n HTTP model calls, ServiceNow flow names, and the
Wudpecker note-taker). A ShadowScan run on the estate after those changes is
in-sample: fewer errors on it are not evidence of better field accuracy. The
[benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md)
lists every benchmark with its protocol and limits.

## The Why

Agents are no longer only Python scripts.
They are Copilot Studio bots built by HR, `n8n` flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock Agents provisioned by Terraform, MCP servers wired into every
developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs carrying an `act` claim.
ShadowScan normalizes these observations into one finding model with evidence,
so investigators or auditors can ask: *Who owns this AI Agent? What can it do, and is it
registered in the agent registry supplied for this scan?*

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
producing a smaller report that looks clean. See
[architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md)
for the pipeline, the package layout and the connector contract.

## Surfaces & connectors

ShadowScan ships **38 connectors** across the nine surfaces below.

| Surface | Connectors | What is discovered |
|---|---|---|
| **Code** | `code.filesystem`, `code.github`, `code.gitlab` | Agent frameworks & LLM SDKs (deps, imports, idioms), MCP client/server configs, coding-agent configs, A2A agent cards, IaC provisioning, CI secrets, hard-coded provider keys (redacted) |
| **Identity** | `identity.okta`, `identity.entra`, `identity.google-workspace`, `identity.auth0`, `identity.jwt` | OAuth apps & consent grants to AI SaaS, service principals / managed identities with LLM or data permissions, JWT classification (human/service/agent) |
| **Gateway** | `gateway.logs`, `gateway.otel` | Callers reconstructed from gateway logs or offline OpenTelemetry GenAI spans |
| **Low-code** | `lowcode.power-platform`, `lowcode.salesforce`, `lowcode.servicenow`, `lowcode.n8n`, `lowcode.make`, `lowcode.zapier`, `lowcode.workato` | Copilot Studio agents, Agentforce, Now Assist, automation workflows with AI steps |
| **SaaS** | `saas.slack`, `saas.microsoft-teams`, `saas.github-apps`, `saas.atlassian`, `saas.notion`, `saas.zoom`, `saas.generic` | Bots and apps with their scopes, install requests, AI coding agents and their permissions |
| **Cloud** | `cloud.aws`, `cloud.gcp`, `cloud.azure`, `cloud.oci`, `cloud.kubernetes`, `cloud.openshift` | Managed cloud AI and IAM inventories, Kubernetes/OpenShift workload exports |
| **Endpoint** | `endpoint.inventory`, `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models`, `endpoint.ebpf` | AI clients and coding agents on workstations with their MCP servers, local model stores, osquery fleet exports |
| **Network** | `network.logs` | AI services contacted per client address from DNS, TLS SNI and flow logs |
| **Runtime** | `runtime.processes` | Coding-agent CLIs, AI apps, MCP servers and local model servers seen running |

Connectors support **live** API collection, **offline** JSON/CSV/log exports,
or both; see the [connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) for supported modes and provider scope.

## Frameworks & products recognized

233 signatures / 1133 signals, YAML-defined with explicit opt-in overrides:

* **Orchestrators** – LangChain, LangGraph, Deep Agents, LlamaIndex, CrewAI, Google ADK, AWS Strands Agents, Microsoft Agent Framework, Semantic Kernel, Microsoft.Extensions.AI, AutoGen/AG2, Hugging Face smolagents and Transformers Agents, OpenAI Agents SDK, OpenAI Swarm, Agency Swarm, Claude Agent SDK, Pydantic AI, Vercel AI SDK, Mastra, Haystack, DSPy, Instructor, Embedchain, Agno, Letta, MetaGPT, CAMEL, Griptape, Composio, Langroid, AgentScope, Swarms, AutoGPT, BabyAGI, BeeAI, Atomic Agents, Julep, Marvin, Mirascope, Qwen-Agent, NVIDIA NeMo Agent Toolkit, Dapr Agents, PraisonAI, SWE-agent, GPT Engineer, Open Interpreter, Chainlit, Prompt flow, Guardrails AI / NeMo Guardrails / LLM Guard, LangChain4j, Spring AI, Koog, Rig, LangChainGo, Genkit, Eino, M365 Agents SDK, Bot Framework, Teams AI, Cloudflare Agents, Inngest AgentKit, VoltAgent, CopilotKit/AG-UI, Rasa, Botpress, Browser Use, Stagehand, OpenHands, Nova Act, Anthropic computer use
* **Protocols** – MCP (all client config locations, servers, registries, remote MCP hosts), A2A agent cards, ACP, tool/function-calling request shapes, ChatGPT plugin/GPT Action manifests
* **Coding agents** – Claude Code, GitHub Copilot coding agent, Devin, Cursor, Windsurf, Cline, Roo, OpenAI Codex, Gemini CLI/Jules, Amazon Q/Kiro, Goose, Aider, Continue, Cody/Amp, Junie, AGENTS.md, PR review bots (CodeRabbit, Sweep, Ellipsis, Greptile, Qodo…)
* **Platforms/gateways** – LiteLLM, Portkey, Kong AI Gateway, Helicone, MLflow AI Gateway, OpenAI AgentKit, Dify, Flowise, Langflow, n8n, Make, Zapier, Workato, Copilot Studio, Power Platform AI connectors, M365 declarative agents, Agentforce, Now Assist, IBM watsonx Orchestrate, Retool, Rivet, Browserbase, Open WebUI/LibreChat/AnythingLLM, Coze/Relevance/Lindy/Vellum…
* **Model providers** – OpenAI, Anthropic, Gemini API, Vertex AI, Bedrock, Azure OpenAI, Mistral, Cohere, Groq, Together, Fireworks, OpenRouter, Ollama, vLLM, SGLang, llama.cpp, LM Studio, LocalAI, Llama Stack, Meta Llama API, Hugging Face, xAI, DeepSeek, Alibaba DashScope/Qwen, Moonshot/Kimi, AI21, Perplexity, Voyage AI, Replicate, Cerebras, SambaNova, NVIDIA NIM, OCI Generative AI, watsonx, Databricks, Cloudflare Workers AI, Snowflake Cortex (deps, imports, endpoints, env vars, user agents, model IDs, **key formats**)
* **Observability/memory/sandboxes** – LangSmith, Langfuse, Phoenix, AgentOps, Traceloop, Weave, Braintrust…, Mem0, Zep, vector stores, E2B, Daytona, web search/scrape tool providers
* **AI SaaS as OAuth apps** – ChatGPT, Claude, Gemini, Copilot, Perplexity, Mistral Le Chat, DeepSeek, Qwen, Kimi, Grok, Poe, Character.ai, Glean, meeting note-takers (Otter, Fireflies, Read.ai, Fathom, tl;dv, Gong…), writing/coding/automation/research/media products, browser AI extensions
* **Permission policies** – privileged, data-access and LLM-access scope classes across Graph, Google, Okta, Slack, GitHub, GitLab, Salesforce, Atlassian, Zoom, Notion, HubSpot, AWS IAM, Azure RBAC, GCP IAM, OCI

`shadowscan signatures list` shows everything; `shadowscan signatures test <value>`
tells you what a package, host, user agent, model ID, scope, or file path maps to.

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

Key fields: **confidence** is a heuristic evidence score (not a calibrated probability). **risk** is additive and explainable: each factor adds up to `score`. **shadow** is `true` unless an inventory entry matches the finding. **autonomy** (`metadata.autonomy`) classifies agents on the L0–L5 scale. **threats** and **controls** are edition-qualified references (OWASP, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act, AIUC-1).

For the full finding schema, risk model, and output format details, see the
[risk scoring](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/risk.md),
[autonomy tiers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/autonomy.md) and
[mappings](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/mappings.md) documentation.

CSV output inserts a literal `'` at the start of a value, and after each `,`, `;`, tab, `|` or line break inside it, when the following text begins with `=`, `+`, `-` or `@` (also after whitespace or quotes), a tab or a carriage return; values beginning with a line feed are also marked. Strip markers for programmatic use or use `json`; see [output and inventory migration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#output-and-inventory-migration).

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

`shadowscan connectors` lists each connector's configuration keys and required
extras; `shadowscan connectors --json` also lists offline export formats. See the
[configuration reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/configuration.md) for all options and the
[connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md) for credential scopes and offline formats.

## Sanctioned inventory

Drop [Agent Cards](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/agent-card.yaml) in a directory and point `inventory:` at it.
Simple `agents.yaml` lists and CSV work too. `shadowscan inventory stubs`
generates card skeletons from shadow findings. See
[docs/inventory.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/inventory.md).

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

## Development

```bash
python -m venv .venv && source .venv/bin/activate
make install          # hash-locked runtime, cloud, dev and docs toolchain
make check            # lint, format, types, signatures, mappings, secrets, audit, coverage, connector floor, evaluation
```

See [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#getting-started)
to get started and its [repository map](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#find-your-way-around)
for where the code, tests, docs, tooling and benchmarks live.

## Evidence and assurance limits

- **Evaluation corpora** are author-written regression cases, not independent field-precision estimates. See [evaluation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md).
- **Benchmarks against other tools** are written by the same maintainer. They show behaviour on those inputs, not field accuracy. See the [benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md).
- **Canaries** validate named tenant controls when credentials are supplied; offline replay does not establish live acceptance. See [canaries](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/canaries.md).
- Review [rollout acceptance](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#rollout-acceptance) before using a risk threshold as a production gate.

## Project status

* **Release state.** Version `0.1.2` is published to PyPI as `NexusShadowScan`
  and tagged `v0.1.2`, as an alpha pre-release. The package classifier is `Development Status :: 3 - Alpha`.
  Commits on `main` after the tag are unreleased.
* **Single maintainer, AI-assisted development.** Apart from Dependabot updates, every commit was written
  by a single maintainer or generated with an AI coding assistant (Claude, Codex, Grok, GitHub Copilot, Google Antigravity, Perplexity, Meta AI, etc.). The logs under
  [archive/reviews/](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/archive/reviews) are AI-assisted, not third-party reviews.
* **Recommendation.** Review the revision yourself or have it reviewed, then
  pin that full commit SHA as shown in
  [Deployment install](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#from-a-reviewed-revision-hash-locked).

## Community and contributing

| I want to… | Start here |
|---|---|
| Ask a question or troubleshoot | [Support guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) |
| Report a bug or request a feature | [Issue forms](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new/choose) |
| Report a false positive or missed framework | [Detection quality report](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=detection_report.yml) |
| Make a first contribution | [Contributor guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md) and [`good first issue`](https://github.com/aisecnomad/Nexus-ShadowScan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) |
| Report a vulnerability privately | [Security policy](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#reporting) |
| Understand participation standards | [Code of conduct](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CODE_OF_CONDUCT.md) |
| See what changed or cite the project | [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

## Safety notes

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data.
* Secret stores (Secrets Manager, Key Vault, Secret Manager, OCI Vault) are read for **names only**.
* JWTs are never persisted; findings reference a truncated hash.
* Built-in collectors inspect provider resources using read operations. Scope the audit identity to the documented read permissions and review any enabled third-party plugin separately.

See [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md) and [docs/production.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md) for deployment behavior, migration and limits.

## License

Apache-2.0. See [LICENSE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and [NOTICE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE).
