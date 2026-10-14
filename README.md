<h1 align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/shadowscan-banner.webp" alt="ShadowScan" width="100%">
</h1>

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/NexusShadowScan?label=PyPI)](https://pypi.org/project/NexusShadowScan/)
[![Python](https://img.shields.io/pypi/pyversions/NexusShadowScan)](https://pypi.org/project/NexusShadowScan/)
[![CI](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml/badge.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml/badge.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-ShadowScan/badge)](https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-ShadowScan)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE)
[![Coverage gate ≥80%](https://img.shields.io/badge/coverage%20gate-%E2%89%A580%25-brightgreen.svg)](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#project-status)

**[Quick start](#quick-start)** · **[How it works](#how-it-works)** · **[Security model](#security-model)** · **[Coverage](#coverage)** · **[Evidence](#evidence-and-benchmarks)** · **[Install](#install)** · **[Docs](#documentation)**

</div>

**ShadowScan is an open-source scanner that discovers evidence of AI agents and
related integrations, then reconciles every finding against the agent registry
you approve.**

It inspects nine surfaces: code repositories, identity providers, LLM gateway
logs, low-code platforms, SaaS apps, cloud accounts, endpoints (developer
workstations and host/runtime inventories), network logs, and running
processes. Every finding carries its evidence, an explainable risk score, an
autonomy tier and its registration status, so an investigator or auditor can
ask three questions of each one: *who owns this agent, what can it do, and did
anyone approve it?*

## Why ShadowScan

Agents are no longer only Python scripts. They are Copilot Studio bots built by
HR, n8n flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock agents provisioned by Terraform, MCP servers wired into every
developer's editor, service principals with `Mail.ReadWrite` acting on behalf
of nobody, and JWTs carrying an `act` claim. Each surface has its own discovery
API and its own vocabulary, and no single team sees all of them. ShadowScan
turns those observations into one finding model with evidence.

- **One model across nine surfaces.** Connectors read live provider APIs or
  analyze offline exports, so the same analysis runs in CI, on an analyst's
  laptop or against a SIEM export.
- **Reconciliation, not just discovery.** Findings are matched against your
  Agent Cards, `agents.yaml` or CSV inventory and against vendor registries you
  choose to trust. A finding that no single explicit binding matches is marked
  `shadow`; an approved entry lends the finding its owner.
- **Explainable risk.** Additive risk factors always sum to the score, and a
  separate `danger_score` ignores registration status. Agents, MCP servers,
  workflows and bots also get an L0–L5 autonomy interval.
- **Fails closed.** API errors, timeouts, limits and malformed exports mark the
  scan incomplete (exit 3) instead of producing a smaller report that looks
  clean.
- **Built for sensitive estates.** Built-in collectors only read. Known
  credential formats are redacted before findings are written, the HTTPS
  client refuses private and metadata addresses by default, and reports are
  written with owner-only permissions.
- **Fits the pipeline you have.** SARIF for code scanning, a CycloneDX 1.6
  AI-BOM, OCSF 1.1.0 events for SIEMs, drift detection between scans, a fleet
  dashboard, and control evidence for NIST AI RMF, ISO/IEC 42001, the EU AI Act
  and AIUC-1.
- **Detection is data.** Product knowledge lives in validated YAML signature
  packs, so recognizing a new framework or vendor is a data change, not a code
  change.

## See it in 60 seconds

The bundled demo runs every fixture-backed connector offline against sample
exports, with no credentials (36 of 38 connectors ship fixtures). It needs a
checkout, because `examples/` and `tests/fixtures/` are not in the wheel:

```bash
git clone https://github.com/aisecnomad/Nexus-ShadowScan.git && cd Nexus-ShadowScan
python -m venv .venv && source .venv/bin/activate
python -m pip install .
shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 7
```

Abridged to the first columns; totals change as signatures evolve:

```console
$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 7

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 133 findings  •  129 shadow (inventory: 4 registered agents)               │
│ critical 16   high 63   medium 54                                          │
│ surfaces: cloud 30, code 12, endpoint 18, gateway 11, identity 19,         │
│           lowcode 15, network 7, runtime 4, saas 17                        │
╰────────────────────────────────────────────────────────────────────────────╯
 CRITICAL 100  SHADOW  code      mcp-server   MCP configuration: .mcp.json
 CRITICAL 100  SHADOW  saas      bot-app      GitHub App installed: claude
 CRITICAL  98  SHADOW  code      agent-config Claude Code configured in repository root
 CRITICAL  91  SHADOW  endpoint  agent-config OpenClaw configured on dev-laptop-07 (~dana)
 CRITICAL  90  SHADOW  code      secret       LLM provider credential in services/research-agent/app/config.py
 CRITICAL  87  SHADOW  endpoint  mcp-server   MCP tool run_command on https://mcp.example.invalid
 CRITICAL  83  SHADOW  cloud     mcp-server   AgentCore Gateway (MCP): tools-gateway
```

Add `--format html -o report.html` for a self-contained report with filters and
evidence drill-down.

## Quick start

Install from PyPI with Python 3.11, 3.12 or 3.13. For a verified or
hash-locked install, see [Install](#install).

```bash
python -m pip install NexusShadowScan             # or: pipx install NexusShadowScan
python -m pip install "NexusShadowScan[cloud]"    # adds the AWS, GCP, Azure and OCI SDKs
```

Start with the surface you want to see first:

```bash
# Code: a checkout (or your whole ~/src); no credentials needed
shadowscan code . --inventory agent-card.yaml
# Pull request scope (Git 2.45+): committed changes only; a diff scan never resolves findings
shadowscan code . --diff-base origin/main

# Developer workstations: well-known AI client locations only, never the whole home directory
shadowscan endpoint --list
shadowscan endpoint --format json -o laptop-$(hostname).json

# Logs and tokens you already have
shadowscan gateway litellm-spend.jsonl bedrock-invocations/ egress-proxy.log
shadowscan jwt --file ./token.jwt --jwks-url https://acme.okta.com/oauth2/default/v1/keys

# One live connector, ad hoc; dump sanitized records to reanalyze offline later
shadowscan run identity.entra --set tenant_id=$AZURE_TENANT_ID
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports

# The whole estate from one configuration file
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif
```

Then operate on the JSON reports (`--format json -o report.json`):

```bash
# Drift: exit 2 on adverse changes against a baseline
shadowscan diff baseline.json today.json --fail-on-drift inventory,capability,autonomy,governance

# Fleet: one report and a static dashboard for every workstation
shadowscan merge laptop-*.json --format json -o fleet.json
shadowscan dashboard fleet.json -o dashboard.html --inventory-json inventory.json

# Governance: an AI bill of materials and control evidence for GRC
shadowscan scan -c shadowscan.yaml --format cyclonedx -o ai-bom.json
shadowscan controls today.json --format csv -o controls.csv

# Registration: Agent Card stubs for every shadow finding, ready for review
shadowscan inventory stubs report.json -o inventory/pending/
```

`agent-card.yaml` and the sample gateway logs under `tests/fixtures/gateway/`
are in the repository checkout, not the wheel. Scanning the ShadowScan checkout
itself reports an incomplete scan (exit 3): its redaction test fixtures
intentionally exceed the sanitizer's limits, and the scanner fails closed
rather than skip them silently. For GitHub Actions, start from the
[consumer workflow example](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/examples/github-action-code-scan.yml);
it fails until the repository variable `SHADOWSCAN_REVISION` holds a reviewed
40-character commit SHA.

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/signature-driven-pipeline.jpg" alt="ShadowScan architecture: YAML signature packs feed a signature index; code, identity, gateway, low-code, SaaS and cloud connectors collect live data or load offline files into records and analyze them into findings; the engine merges and correlates findings across surfaces, reconciles them with the inventory, scores risk and sorts; reporters write table, JSON, SARIF, CSV, Markdown and HTML." width="100%">
</p>

1. **Collect.** Each connector turns a live provider API (`collect()`) or an
   offline export (`load_offline()`) into records. Sanitized record dumps can
   be reanalyzed later without credentials.
2. **Analyze.** `analyze()` matches records against the signature index:
   dependencies, imports, code idioms, files, environment variables, domains,
   user agents, container images, IaC resources, names, permission scopes,
   model IDs, secret formats and client IDs. Each match becomes weighted
   evidence.
3. **Merge, correlate and reconcile.** The engine merges findings with the same
   stable identity and links them across surfaces: the Terraform that
   provisions an agent, the agent in the account, the role that calls Bedrock.
   It checks MCP servers against the registry snapshots you pin, then
   reconciles each finding with your inventory and the vendor registries you
   trust.
4. **Assess.** Findings get an autonomy interval and an additive risk score
   scaled by confidence; threat and control references are added where they
   apply.
5. **Report.** Reporters write the sorted result. JSON reports feed `diff`,
   `merge`, `dashboard`, `controls` and `inventory stubs`.

Every stage except the opt-in LLM triage fails closed: a gap it cannot fill
makes the scan incomplete (exit 3). Triage only adds an advisory verdict to the
highest-risk findings and never changes scores. The diagram is simplified: its
connector row shows six of the nine surface families, and reporters also write
CycloneDX and OCSF. [Architecture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/architecture.md)
documents the pipeline, the package layout and the connector contract.

## Security model

A discovery scanner holds read access to your most sensitive systems, so its
own trust boundaries are explicit.

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/trust-boundaries-and-data-flow.jpg" alt="Trust boundaries and data flow of one scan: untrusted provider APIs, offline exports and repository checkouts feed records to the connectors; trusted signature packs, configuration and the inventory are operator inputs; the engine merges, correlates, reconciles and scores under a supervisor with per-connector deadlines; reports, sanitized record dumps and scan state are written atomically with private file modes." width="100%">
  <br>
  <sub>Tinted boxes are trusted operator inputs; dashed boxes are untrusted scan targets; arrows show the data flow of one scan. Six of the nine surface families are drawn.</sub>
</p>

| Trusted | Untrusted |
|---|---|
| The operator workstation or CI runner, the scan configuration and installed Python packages | Provider API responses, scanned repositories, offline exports and logs |
| Signature packs you reviewed, and plugins you allowlisted by exact name: an allowlisted plugin runs with scanner privileges, and the allowlist is not a sandbox | Third-party plugins; none runs without an exact-name allowlist entry |

What the scanner does by default:

- **Collects read-only.** Built-in collectors use read operations. Give each
  audit identity only the
  [documented read permissions](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md),
  and review any third-party plugin you allowlist separately.
- **Keeps credential boundaries apart.** Repository scans and live tenant
  collection run as separate scans unless you set `allow_credential_mixing`.
  Cloud instance-metadata credentials need `allow_instance_credentials`.
- **Constrains the network.** The shared HTTPS client keeps redirects and
  pagination on the configured origin, refuses private, loopback, link-local
  and metadata addresses unless you set `allow_private_origin`, and bounds
  response size and read time.
- **Minimizes what it keeps.** Known credential formats, sensitive
  configuration fields and credential-bearing URLs are redacted before findings
  or record exports are written. Secret stores are read for names only. JWTs
  are never persisted; findings reference a truncated hash.
- **Writes privately.** Reports and inventory stubs are written atomically with
  mode 0600, record exports go to 0700 directories, and signature and inventory
  directory walks do not follow symbolic links.
- **Sends nothing to a model unless you ask.** LLM triage is off by default.
  Enabled, it sends a sanitized summary of the highest-risk findings to the
  model endpoint you configure, with resource IDs, owners, accounts and file
  locations withheld; do not enable it for findings that must not leave your
  environment ([what the model sees](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/llm-triage.md)).

Redaction cannot recognize every arbitrary secret, and a report describes your
AI estate in detail: treat reports as confidential. The complete controls and
their limits are in [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#trust-boundary)
and [production deployment](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md).

## Coverage

ShadowScan ships **38 connectors** across nine surfaces. Each supports live API
collection, offline JSON, CSV or log exports, or both; the
[connector guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md)
lists modes, configuration keys and least-privilege scopes, and
`shadowscan connectors` prints them for the installed version.

| Surface | Connectors | What it discovers |
|---|---|---|
| **Code** | `code.filesystem` `code.github` `code.gitlab` | Agent frameworks and LLM SDKs (dependencies, imports, idioms), MCP client and server configurations, coding-agent configurations (Claude Code, Copilot custom agents, Cursor, Codex, Gemini CLI…), A2A agent cards, M365 declarative agents, exported n8n, Flowise, Langflow and Dify flows, IaC that provisions Bedrock, Vertex, Foundry or OCI agents, container images, CI secret names, hard-coded provider keys (redacted) |
| **Identity** | `identity.okta` `identity.entra` `identity.google-workspace` `identity.auth0` `identity.jwt` | OAuth apps and consent grants to AI SaaS; service apps, service principals and managed identities with LLM or data permissions; app registrations that look like agents; JWTs classified as human, service, workload or delegated agent, with privilege and hygiene analysis |
| **Gateway** | `gateway.logs` `gateway.otel` | Callers reconstructed from gateway logs or offline OpenTelemetry GenAI spans; span prompt and completion content is not retained |
| **Low-code** | `lowcode.power-platform` `lowcode.salesforce` `lowcode.servicenow` `lowcode.n8n` `lowcode.make` `lowcode.zapier` `lowcode.workato` | Copilot Studio agents and topics, Power Automate and Power Apps using AI connectors, Agentforce planners and actions, Einstein bots, prompt templates, Now Assist agents, and automation workflows with AI or agent steps |
| **SaaS** | `saas.slack` `saas.microsoft-teams` `saas.github-apps` `saas.atlassian` `saas.notion` `saas.zoom` `saas.generic` | Bots and apps with their scopes, pending install requests, Teams apps with bots or Copilot agents, GitHub Apps (AI reviewers, coding agents), Rovo and Marketplace apps, Notion integrations, Zoom Marketplace apps (approval does not prove installation), and any CSV or JSON app inventory such as a CASB export |
| **Cloud** | `cloud.aws` `cloud.gcp` `cloud.azure` `cloud.oci` `cloud.kubernetes` `cloud.openshift` | Managed AI and IAM inventories, plus offline Kubernetes and OpenShift workload exports (images, exposure, GPU, privilege and egress-policy indicators) |
| **Endpoint** | `endpoint.inventory` `endpoint.host` `endpoint.mcp` `endpoint.ollama` `endpoint.models` `endpoint.ebpf` | AI clients and coding agents configured in home directories with their MCP servers and posture, AI editor and browser extensions, local model stores, opt-in shell-history tool counts, osquery fleet exports, and offline host, MCP tool-list, model metadata and eBPF event exports |
| **Network** | `network.logs` | AI services contacted per client address, from Zeek, Route 53 Resolver, VPC Flow Logs or generic DNS and SNI exports, with strict host matching, DNS-attributed flows that refuse shared CDN addresses, and agent-service and agent-loop indicators |
| **Runtime** | `runtime.processes` | Coding-agent CLIs, AI desktop apps, MCP servers, local model servers and agent dev servers seen running, from osquery, Defender or CrowdStrike process exports or `/proc`; command lines are never kept, and processes are linked to the endpoint findings for the same tool on the same device |

The offline inventories (`endpoint.host`, `endpoint.mcp`, `endpoint.ollama`,
`endpoint.models`, `endpoint.ebpf`, `gateway.otel`, `cloud.kubernetes`,
`cloud.openshift`) analyze exports; they do not probe MCP or Ollama endpoints,
call a Kubernetes API or parse model files. The one opt-in exception is
`endpoint.mcp`, which fetches the A2A Agent Cards of agents listed in
`agent_card_urls`. With no `input`, `endpoint.inventory` reads a fixed list of
local user-scope locations (model stores are listed by file name, never parsed)
and `runtime.processes` reads `/proc` on Linux.

### Frameworks and products recognized

Detection knowledge is data: 233 signatures and 1,133 signals in YAML packs
recognize frameworks, model providers, protocols, coding agents, platforms,
identity apps and permission policies. `shadowscan signatures list` shows them
all, and `shadowscan signatures test <value>` tells you what a package, host,
user agent, model ID, scope or file path maps to.

<details>
<summary><b>The full list</b></summary>

* **Orchestrators** – LangChain, LangGraph, Deep Agents, LlamaIndex, CrewAI, Google ADK, AWS Strands Agents, Microsoft Agent Framework, Semantic Kernel, Microsoft.Extensions.AI, AutoGen/AG2, Hugging Face smolagents and Transformers Agents, OpenAI Agents SDK, OpenAI Swarm, Agency Swarm, Claude Agent SDK, Pydantic AI, Vercel AI SDK, Mastra, Haystack, DSPy, Instructor, Embedchain, Agno, Letta, MetaGPT, CAMEL, Griptape, Composio, Langroid, AgentScope, Swarms, AutoGPT, BabyAGI, BeeAI, Atomic Agents, Julep, Marvin, Mirascope, Qwen-Agent, NVIDIA NeMo Agent Toolkit, Dapr Agents, PraisonAI, SWE-agent, GPT Engineer, Open Interpreter, Chainlit, Prompt flow, Guardrails AI / NeMo Guardrails / LLM Guard, LangChain4j, Spring AI, Koog, Rig, LangChainGo, Genkit, Eino, M365 Agents SDK, Bot Framework, Teams AI, Cloudflare Agents, Inngest AgentKit, VoltAgent, CopilotKit/AG-UI, Rasa, Botpress, Browser Use, Stagehand, OpenHands, Nova Act, Anthropic computer use
* **Protocols** – MCP (all client config locations, servers, registries, remote MCP hosts), A2A agent cards, ACP, tool/function-calling request shapes, ChatGPT plugin/GPT Action manifests
* **Coding agents** – Claude Code, GitHub Copilot coding agent, Devin, Cursor, Windsurf, Cline, Roo, OpenAI Codex, Gemini CLI/Jules, Amazon Q/Kiro, Goose, Aider, Continue, Cody/Amp, Junie, AGENTS.md, PR review bots (CodeRabbit, Sweep, Ellipsis, Greptile, Qodo…)
* **Platforms and gateways** – LiteLLM, Portkey, Kong AI Gateway, Helicone, MLflow AI Gateway, OpenAI AgentKit, Dify, Flowise, Langflow, n8n, Make, Zapier, Workato, Copilot Studio, Power Platform AI connectors, M365 declarative agents, Agentforce, Now Assist, IBM watsonx Orchestrate, Retool, Rivet, Browserbase, Open WebUI/LibreChat/AnythingLLM, Coze/Relevance/Lindy/Vellum…
* **Model providers** – OpenAI, Anthropic, Gemini API, Vertex AI, Bedrock, Azure OpenAI, Mistral, Cohere, Groq, Together, Fireworks, OpenRouter, Ollama, vLLM, SGLang, llama.cpp, LM Studio, LocalAI, Llama Stack, Meta Llama API, Hugging Face, xAI, DeepSeek, Alibaba DashScope/Qwen, Moonshot/Kimi, AI21, Perplexity, Voyage AI, Replicate, Cerebras, SambaNova, NVIDIA NIM, OCI Generative AI, watsonx, Databricks, Cloudflare Workers AI, Snowflake Cortex (dependencies, imports, endpoints, environment variables, user agents, model IDs and **key formats**)
* **Observability, memory and sandboxes** – LangSmith, Langfuse, Phoenix, AgentOps, Traceloop, Weave, Braintrust…, Mem0, Zep, vector stores, E2B, Daytona, web search and scrape tool providers
* **AI SaaS as OAuth apps** – ChatGPT, Claude, Gemini, Copilot, Perplexity, Mistral Le Chat, DeepSeek, Qwen, Kimi, Grok, Poe, Character.ai, Glean, meeting note-takers (Otter, Fireflies, Read.ai, Fathom, tl;dv, Gong…), writing, coding, automation, research and media products, browser AI extensions
* **Permission policies** – privileged, data-access and LLM-access scope classes across Graph, Google, Okta, Slack, GitHub, GitLab, Salesforce, Atlassian, Zoom, Notion, HubSpot, AWS IAM, Azure RBAC, GCP IAM and OCI

</details>

## Reading a finding

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
      {"signal": "secret: provider.openai", "description": "Plaintext OpenAI API key in environment variable OPENAI_API_KEY: sk-p…KLMN", "weight": 0.6}],
  "metadata": {"status": "READY", "protocol": "HTTP", "network": "PUBLIC", "related": ["ss-…"],
      "threats": ["maestro-2025:L3", "mitre-atlas-2026.09:AML.T0055", "owasp-asi-2026:ASI03", "owasp-llm-2026:LLM02"],
      "controls": ["aiuc-1-2026q2:B", "aiuc-1-2026q2:E", "eu-ai-act-2024:Art.15", "..."]}
}
```

| Field | What it means |
|---|---|
| `confidence` | A heuristic evidence score, not a calibrated probability or proof that an agent executed. Correlated evidence is grouped and each group counts once at its strongest weight before a noisy-OR combination ([ADR-003](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/adrs/003-evidence-based-confidence.md)). |
| `risk` | Additive and explainable: kind, capabilities (code execution, autonomy, SaaS actions…), permission classes, credential exposure, exposure and auditability tags, registration and ownership, scaled by confidence. The listed factors always add up to `score`, including the confidence scaling and the 0–100 bounds. |
| `danger_score` | The same model without the governance factors (registration and ownership): what the agent can do, whether or not anyone approved it. |
| `shadow` | `true` unless exactly one inventory entry matches an explicit resource pattern and its configured scope restrictions. Names only suggest entries for review. |
| `metadata.autonomy` | An interval on the L0 Chatbot to L5 Fully Autonomous scale: the `floor` the evidence proves and the `ceiling` it has not ruled out, with `oversight`, `initiation` and the rules behind them ([autonomy tiers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/autonomy.md)). |
| `metadata.potential_capabilities` | Framework features supported only by availability evidence, such as an import or a dependency. They are excluded from capability risk factors until stronger source evidence supports them. |
| `metadata.related` | Links across surfaces: the Terraform that provisions an agent, the agent in the account, the role calling Bedrock, the CloudTrail caller. |
| `metadata.threats`, `metadata.controls` | Edition-qualified OWASP, MITRE ATLAS and MAESTRO references and NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 controls. They are evidence references and author mappings, not compliance determinations ([mappings](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/mappings.md)). |

A finding is evidence, not a verdict. Read it with its next check:

| Observation | What it establishes | Next check |
|---|---|---|
| Source dependency, import, or configuration | A repository contains a potential integration. | Inspect executable code and deployment; comments, examples, and unused dependencies can mislead. |
| Cloud or SaaS resource | The collector observed a configured resource within its granted scope. | Check resource state and authenticated runtime telemetry before claiming execution. |
| Gateway event | The supplied log contains a request or tool-use signal. | Verify the log's origin, caller binding, and observation window before attributing it to a deployed agent. |
| `shadow: true` | No single explicit binding in the **supplied** inventory matched the finding. | Confirm the inventory's scope and freshness; an unmatched finding alone does not prove unauthorized use. |

## Outputs and integrations

| Format | Use it for |
|---|---|
| `table` | Terminal triage |
| `json` | Automation, and the input to `diff`, `merge`, `dashboard`, `controls` and `inventory stubs` |
| `sarif` | GitHub code scanning. Code findings carry `file:line` locations; results are warnings or notes with the heuristic risk level, never a CVSS `security-severity` ([severity](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md)) |
| `csv` | Spreadsheets and GRC tools, with formula markers described below |
| `markdown` | Issues and pull requests, with untrusted links and mentions defanged |
| `html` | A self-contained, filterable report with evidence drill-down |
| `cyclonedx` | A CycloneDX 1.6 AI bill of materials ([AI-BOM](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ai-bom.md)) |
| `ocsf` | OCSF 1.1.0 Detection Finding events for SIEMs and security data lakes ([OCSF](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/ocsf.md)) |

After a scan, `shadowscan diff` reports new, resolved and changed findings with
drift classes; missing findings resolve only between complete, comparable
scans ([drift](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/drift.md)).
`shadowscan merge` combines workstation reports into a fleet report, and
`shadowscan dashboard` renders it as a static page (coverage per source first,
autonomy against shadow status, registry reconciliation, drift and history)
plus a versioned `shadowscan.inventory/v1` JSON export for BI and SIEM tools
([fleet dashboard](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/dashboard.md)).
`shadowscan controls` lists, for each NIST AI RMF, ISO/IEC 42001, EU AI Act and
AIUC-1 control, the findings that reference it. A control no finding references
reads "not observed" only when every input is complete and no finding could
reference it through a missing inventory or an undeclared risk class, and
"unknown" otherwise; an incomplete input exits 3
([control evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/controls.md)).
Opt-in [LLM triage](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/llm-triage.md)
adds an advisory model verdict to the highest-risk findings; it is off by
default and never changes scores.

<details>
<summary><b>Formula markers in CSV and defanging in Markdown</b></summary>

CSV inserts a literal `'` at the start of a value, and after each `,`, `;`,
tab, `|` or line break inside it, when the following text begins with `=`,
`+`, `-` or `@` (also after whitespace or quotes), a tab or a carriage return;
values beginning with a line feed are also marked. Other tabs and line breaks
remain unchanged, and spreadsheet cells are read as text regardless of
delimiter. Strip markers for programmatic use or use `json`; see
[output and inventory migration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#output-and-inventory-migration).

`markdown` output defangs links (`hxxps://`, `www[.]`) and writes `@` as `[@]`
in untrusted text, so a report pasted into an issue or pull request creates no
links, @-mentions or e-mail links; code spans keep identifiers verbatim.

</details>

## Evidence and benchmarks

> **Read this first.** The maintainer who wrote ShadowScan also wrote every
> benchmark below: the corpora, the labels, the adapters that run the other
> tools, and the scoring. None of them is independent, and none estimates
> precision or recall in the field. They show how tools behave on the listed
> inputs, and every input is committed and hashed so that someone without a
> stake can rerun them with their own seed, families or labels.

<p align="center">
  <img src="https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/head-to-head-estate-recall.webp" alt="Bar chart of estate recall on the synthetic head-to-head benchmark, where unsupported surfaces count as misses: ShadowScan 0.90, Cisco AI BOM 0.49, AgentSonar 0.33, agent-bom 0.29, Shadow AI Detector 0.28, AgentDiscover 0.23, Open Shadow AI 0.19, Snyk Agent Scan 0.18, AI-Detector 0.13, Cisco MCP Scanner 0.04, Claw-Hunter 0.04." width="100%">
  <br>
  <sub>Synthetic head-to-head: 900 generated cases (300 repositories, 300 developer home directories, 300 egress logs), eleven tools with no network access, the ten besides ShadowScan at upstream commits taken on 2026-10-06. Estate recall counts each surface a tool does not support as a miss, so it rewards breadth: a tool that supports one of the three surfaces cannot exceed 0.33.</sub>
</p>

The chart answers *how much of this estate does one tool cover*, not *which
tool detects best*. The [report](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/benchmark/results/REPORT.md)
has per-surface precision and recall with intervals and paired McNemar tests,
and the [method](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/benchmark/README.md)
lists how each tool was run and the limits. Four of the committed benchmarks,
with ShadowScan's weak spots next to its results:

| Benchmark | Inputs | ShadowScan | Where ShadowScan fell short |
|---|---|---|---|
| [ShadowBench synthetic](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/synthetic/README.md) ([2026-10-11 run](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/synthetic/results/2026-10-11/REPORT.md)) | 346 generated, platform-native cases on nine surfaces: 738 expected entities and 735 decoys | The only one of nine tools to run on every surface: estate recall 84%, in-scope entity F1 83% | Specificity of 57% on identity and 33% on SaaS, because it reports admin-scoped service identities and non-AI workspace bots; it missed Entra Agent ID objects and Langflow and OpenClaw images on Kubernetes |
| [ShadowBench estate](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/estate/README.md) ([2026-10-11 run](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadowbench/estate/results/2026-10-11/REPORT.md)) | Vendor-format artifacts of one fictional organization: 137 labeled entities across nine surfaces | Entity precision 91%, recall 95%, F1 93% | 8 false positives among 50 controls and near-misses; missed self-hosted model servers reached without a vendor marker and a Slack note-taker |
| [Code surface](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadow-ai-discovery/README.md) ([2026-10-09 results](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/shadow-ai-discovery/results/2026-10-09/REPORT.md)) | 87 public repositories pinned by commit | In-scope value-level F1 97%; flagged none of 10 controls and 12 near-misses | 43 runs were incomplete (exit 3), so their facts are lower bounds |
| [Synthetic head-to-head](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/benchmark/README.md) ([results](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/benchmark/results/REPORT.md)) | 900 generated cases on three surfaces | Estate recall 0.90 | Endpoint recall 0.70; on egress logs it found every AI case but labeled none as an agent. Its perfect repository score on a corpus its own maintainer wrote is a reason for suspicion |

Only the code-surface benchmark runs in automation: a weekly
[workflow](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/benchmark.yml)
fails on a regression against the newest committed baseline. The
[benchmark index](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/benchmarks/README.md)
describes all of them.

**Before you gate on a risk threshold**, establish it for your environment
with a [frozen, independently adjudicated holdout](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md#gate-a-frozen-holdout)
and a [read-only tenant canary](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/evaluation.md#read-only-tenant-canary-procedure).
The repository's own assurance evidence has limits you should know:

- **Regression corpora** (`make evaluate`) are author-written cases, including
  multi-file cases with documented misses. Detection quality depends on
  repositories, providers, tenant permissions and log provenance.
- **The assurance corpus** is a frozen set of 42 public files (30 negatives)
  labeled by two AI reviewers before evaluation. The labelers share model
  capabilities, so these are not independent human ground truth, and only the
  baseline is out of sample ([assurance results](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/assurance-results.md)).
- **[Canaries](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/canaries.md)**
  for AWS and Slack validate named tenant controls when approved read-only
  credentials are supplied; offline replay does not establish live tenant
  acceptance.
- **The [acceptance verifier](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/acceptance/README.md)**
  requires current source and signature identities, declared human-reviewed
  holdout evidence and live tenant receipts. It validates supplied evidence but
  cannot authenticate reviewer independence or manufacture tenant acceptance.

## Install

### From PyPI

```bash
python -m pip install NexusShadowScan            # or: pipx install NexusShadowScan
python -m pip install "NexusShadowScan[cloud]"   # adds the AWS, GCP, Azure and OCI SDKs
shadowscan --help
```

The distribution is `NexusShadowScan`; the command and Python imports are
`shadowscan`. The unrelated `shadowscan` package on PyPI is not this project.
Python 3.11, 3.12 or 3.13 is required. CI tests every supported version on
Linux and the oldest and newest on macOS; Linux x86_64 is the validated
deployment target, and 3.14 is excluded until the CI matrix and hash-locked
dependency sets cover it. Core dependencies are `click`, `rich`, `PyYAML`,
`requests`, `urllib3`, `PyJWT[crypto]` and `regex`. Cloud SDKs are optional
extras; every cloud connector also accepts an offline record dump.

### Verify the published wheel

Releases are uploaded only by the maintainer-approved
[publish job](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/release.yml)
through PyPI trusted publishing, and the uploaded wheel is the file that job
attests on GitHub:

```bash
python -m pip download --no-deps --dest wheels NexusShadowScan==0.1.2
gh attestation verify wheels/nexusshadowscan-0.1.2-py3-none-any.whl --repo aisecnomad/Project-Nexus
```

The 0.1.2 attestation was signed under this repository's former name,
`aisecnomad/Project-Nexus`, so verify against that name; GitHub redirects it to
`Nexus-ShadowScan`. The source version string is not, by itself, evidence of a
published or signed artifact; the package index and the release evidence are.
A plain `pip install` also resolves dependencies from the live index, so use
the hash-locked install below for a deployment.

### Deployment install (reviewed revision, hash-locked)

Select the full 40-character commit SHA after reviewing its changes and CI
results, and set `SHADOWSCAN_REVISION` to it; do not use a moving branch or an
unpublished tag in a deployment job. From a clean checkout and virtual
environment, install the checked-in runtime and build locks, then build and
install the wheel:

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Nexus-ShadowScan.git
cd Nexus-ShadowScan
git checkout --detach "$SHADOWSCAN_REVISION"
test "$(git rev-parse HEAD)" = "$SHADOWSCAN_REVISION"
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m pip install --no-deps dist/nexusshadowscan-*.whl
```

The runtime lock includes the core scanner and cloud dependencies and is
validated for Linux x86_64 with Python 3.11 to 3.13. Build and retain the wheel
from the reviewed commit; see
[locked installs and release evidence](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#install-from-a-reviewed-revision)
for validation and artifact retention. To run in a container, build the
[Dockerfile](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md#docker)
from the same reviewed revision; its base image is pinned by digest.

### Development install (non-reproducible)

For development only, a VCS install resolves transitive dependencies at install
time. It is not hash-locked or reproducible and must not be used for deployment
or CI gating.

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
python -m pip install "git+https://github.com/aisecnomad/Nexus-ShadowScan.git@${SHADOWSCAN_REVISION}"
python -m pip install "NexusShadowScan[cloud] @ git+https://github.com/aisecnomad/Nexus-ShadowScan.git@${SHADOWSCAN_REVISION}"
```

## Configuration

```yaml
# shadowscan.yaml
inventory: [./inventory]               # Agent Cards, agents.yaml or CSV
signatures: [./custom-signatures]      # optional: extra packs; overrides require opt-in
options:
  plugins: []                          # exact names of reviewed third-party connectors
  allow_signature_override: false
  allow_private_origin: false          # opt in only for trusted private HTTPS APIs
  allow_credential_mixing: false       # separate repository scans from live tenant access
  allow_instance_credentials: false    # cloud metadata credentials require explicit opt-in
  connector_timeout_seconds: 120       # soft deadline; also enforce a host job timeout
  parallel: 4                          # worker threads; use 1-2 for CPU-bound offline scans
  min_confidence: 0.3
  dump_records: ./exports              # sanitized records for offline re-runs; excludes JWTs
connectors:
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: identity.google-workspace
    service_account_file: ./sa.json
    admin_email: admin@acme.com
  - name: gateway.logs
    label: litellm-prod                # names this entry in --only, progress and exports
    input: ./exports/litellm-spend.jsonl
  - name: lowcode.power-platform
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    enabled: false                     # keep the entry, skip it on this run
    token: ${SLACK_TOKEN}
  - name: cloud.aws
    regions: [us-east-1, eu-west-1]
    cloudtrail_days: 7
```

`shadowscan connectors` lists each connector's configuration keys and required
extras, and `shadowscan connectors --json` adds the offline export formats.
Every entry accepts `enabled` (default `true`) and `label`, a distinct ID when
a connector runs more than once. See
[connector keys and least-privilege scopes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors.md)
and the [configuration key reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/connectors/reference.md).

**Credential boundaries.** Run repository scans separately from live tenant
collection. Mixing them requires the explicit `allow_credential_mixing`
exception; keep them separate for untrusted repositories. Cloud
instance-metadata credentials require `allow_instance_credentials: true`; use
an explicit audit identity by default.

### Exit codes

| Exit | Meaning |
|---|---|
| **3** | Scan incomplete. `shadowscan diff` also returns 3 when reports are incomparable, for example live scans other than complete, attested `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` collections, or an expired or undatable baseline with `--max-baseline-age-days`. |
| **2** | Scan completed but reached `--fail-on`. `shadowscan diff` returns 2 for new findings or a higher risk level with `--fail-on-new`, and for adverse drift with `--fail-on-drift`. |
| **1** | No scan result: invalid option, value, path or configuration, or setup/output error. |
| **0** | Scan completed and passed. |

Gate CI on any non-zero exit. SARIF marks incomplete scans unsuccessful while
preserving findings from successfully assessed inputs. Enable `--fail-on` only
after a holdout and a tenant canary establish an acceptable threshold for that
environment (see [Evidence and benchmarks](#evidence-and-benchmarks)). A
complete static scan does not prove agent execution or collection of every
eligible resource. `--job-deadline-seconds` (`options.job_deadline_seconds`)
bounds the whole CLI process, setup and output included, and exits 3 when it
expires; it does not reap subprocesses, so still enforce a host job timeout for
hard limits. Confidence thresholds must be finite numbers from 0 to 1; invalid
CLI or YAML values stop the scan before the risk gate runs.

<details>
<summary><b>Coverage policy: what makes a scan incomplete</b></summary>

Oversize files the scanner would inspect and symbolic links that leave the scan
root make coverage incomplete (exit 3) by default. `--strict-coverage`
(`strict_coverage: true`) records them as errors instead of warnings;
`oversize_skip_globs` remain declared warnings. An in-root link is complete when
its name is never read (for example, a lockfile or image), or when it is a source
file whose target is analyzed in the same project with the same test
classification. Directory links are incomplete because their alias paths are
not scanned. A file analyzed by name but unreadable as text (dense NUL bytes,
mostly invalid UTF-8, or UTF-16 or UTF-32 without a byte-order mark) is also a gap;
legacy-encoded text and a few stray NUL bytes are analyzed with a warning. Non-empty
`bin/`, `build/`, `dist/`, `vendor/` and similar directories skipped by default
are listed in a warning; `--no-default-excludes` scans them. Evidence found only
in test or fixture code cannot establish an agent unless `--include-tests` is set.
The CLI normally exits promptly after a connector deadline even if a blocked
worker cannot be joined; filesystem publication already in progress can delay
timeout handling. See [scan semantics](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md)
for the full coverage policy.

</details>

<details>
<summary><b>Incremental scans, runtime correlation and git history</b></summary>

Use `--incremental` to reuse completed scans of unchanged local checkouts and
static cloud exports. Live APIs and gateway logs are refreshed on each run.
Configure `gateway.logs.correlation_bindings` to link a code resource to a
specific gateway caller and scope. Matching timestamped framework fingerprints
then appear in `metadata.runtime_activity`, including the observation window and
any production label claimed in the logs. Treat caller and environment fields
according to export provenance; ShadowScan does not authenticate an imported
log's source. See [scan state and runtime correlation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md)
for configuration and limitations.

Git history enrichment is disabled by default. Set connector `use_git: true`
only for a reviewed local checkout when author/history metadata is needed;
metadata commands cannot fetch missing objects. Every explicit `--only` selector
must match an enabled connector name or label. Unsupported records and saved API
error responses cannot establish an empty, successful inventory.

</details>

**Upgrading baselines.** After upgrading from reports without the v2
finding-identity schema, regenerate your comparison baseline. Findings retain
identity when inferred classification changes; legacy baselines cannot
establish resolution under the new schema. See
[deployment and migration](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md)
for rollout checks.

### Risk policy

```yaml
options:
  risk_basis: danger    # combined (default) | danger: level from capabilities, not registration
  # Weights are integers from -100 to 100. Unknown groups, kinds, capabilities,
  # provider ids, governance or autonomy keys are rejected; tags may be custom.
  risk_weights:
    capabilities: {code-exec: 25}
    tags: {meeting-bot: 20}
    providers: {provider.deepseek: 20}
    kinds: {agent: 20}
    # governance also takes mcp-not-in-approved-registry (options.mcp_registries)
    governance: {shadow: 15, no-owner: 5, registered: -10}
    autonomy: {L4: 10, L5: 20}    # observed autonomy floor L0..L5; every level defaults to 0
```

`risk_basis: danger` bases `level` and `--fail-on` on `danger_score` instead of
the combined score. See [risk scoring](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/concepts/risk.md).

## Sanctioned inventory

Drop your Agent Cards in a directory. The card's `metadata.agent_id` identifies
the registration; explicit `discovery.resources` bind it to concrete resources:

```yaml
metadata:
  agent_id: "ops-provisioning-04"
  owner_team: "Platform-Engineering"
discovery:
  resources:
    - "arn:aws:bedrock:*:123456789012:agent/AGENT1"
    - "github:acme/infra-agents/*"
  names: ["ops provisioning agent"]
```

Simple `agents.yaml` lists and CSV work too. A card with `schema_version: 2`
declares `autonomy_profile.level` (0 to 5), and a declared level below the
observed floor adds the `autonomy-understated` tag; an older card's level is
ignored with a warning. Such a card may also declare governance facts the
scanner cannot observe (EU AI Act risk class, intended purpose, oversight
measures, AIUC-1 certificate, ISO/IEC 42001 scope); reports label them
declared. `shadowscan inventory stubs` turns shadow findings into card
skeletons for review, and `shadowscan inventory check` validates inventory
files. See [inventory](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/inventory.md).

## Extending ShadowScan

* **Signatures** are YAML. Add a pack directory with `--signatures` or
  `signatures:` to recognize new products; replacing a built-in signature
  requires explicit opt-in. Validate packs with
  `python -m shadowscan.signatures.validate`; the schema and authoring guide
  are in [signatures](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/signatures.md).
* **Connectors** implement `collect()` (live) and `analyze()` (records to
  findings) and register through the `shadowscan.connectors` entry-point group.
  Execution requires an exact-name `options.plugins` entry (or
  `--allow-plugin`), which can also pin the import target and the distribution
  version. `plugin_execution: process` runs each plugin in a worker the scanner
  can kill at its deadline; that is lifecycle isolation, not a sandbox, because
  a plugin keeps the scanner's privileges. See
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

## Project status

* **Release state.** Version `0.1.2` is published to PyPI as `NexusShadowScan`
  and tagged `v0.1.2`, as an alpha pre-release. Verify the artifact identity on
  [PyPI](https://pypi.org/project/NexusShadowScan/0.1.2/) and the
  [GitHub release](https://github.com/aisecnomad/Nexus-ShadowScan/releases/tag/v0.1.2)
  before installing from the production index; publication does not establish
  independent review or deployment acceptance. Commits on `main` after the tag
  are unreleased. The package classifier is `Development Status :: 3 - Alpha`.
* **Single maintainer, AI-assisted development.** Apart from Dependabot
  updates, every commit was written by a single maintainer or generated with an
  AI coding assistant (Claude, Codex, Grok, GitHub Copilot, Google Antigravity,
  Perplexity, Meta AI, etc.). The logs under
  [archive/reviews/](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/archive/reviews)
  are AI-assisted, not third-party reviews, and green CI, CodeQL or the
  Scorecard is not evidence that a second person reviewed a change.
* **Recommendation.** Review the revision yourself or have it reviewed, then
  pin that full commit SHA as shown in
  [Deployment install](#deployment-install-reviewed-revision-hash-locked).
  Review state cannot be established from a checkout; verify it with the
  commands in
  [merge gate and review status](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md#merge-gate-and-review-status).
  External reviewers can start from the
  [reviewer packet](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/operations/reviewer-packet.md).

## Community and contributing

Contributions are welcome from developers, security practitioners, technical
writers and people testing the scanner against their own authorized data. A
small documentation fix or a reproducible false-positive report is useful.

| I want to… | Start here |
|---|---|
| Learn, ask a question or troubleshoot a scan | [Support guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) |
| Report a bug, request a feature, or request a connector | [Issue forms](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new/choose) |
| Report a false positive, a missed framework, or a wrong score | [Detection quality report](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=detection_report.yml) |
| Make a first contribution | [Contributor guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#getting-started) and the [`good first issue`](https://github.com/aisecnomad/Nexus-ShadowScan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label |
| Run the quality gates locally | `make install` then `make check`; see [quality gates](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates) |
| Understand decisions, review and release requirements | [Governance](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md), [Maintainers](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/MAINTAINERS.md), [Roadmap](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/ROADMAP.md) |
| Understand participation standards or report harmful conduct | [Code of conduct](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CODE_OF_CONDUCT.md) |
| See what changed, or cite the project | [Release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md), [Changelog](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CITATION.cff) |

Use synthetic, minimal examples in public reports. Scan results can contain
credentials, personal data and sensitive inventory even after redaction.

## Reporting a vulnerability

Report security issues privately through a GitHub security advisory, never in a
public issue. [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#reporting)
explains what to report, what to include and how disclosure works.

## License

Apache-2.0. See [LICENSE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE)
and [NOTICE](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE).
