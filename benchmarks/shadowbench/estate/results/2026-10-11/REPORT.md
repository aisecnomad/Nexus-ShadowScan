# ShadowBench: shadow AI agent discovery estate benchmark

Corpus: 137 labeled entities across the nine surfaces (87 positive carrying 104 expected facts, 27 control, 23 near-miss; 4 positives are registered in the supplied agent registry).
Run started 2026-10-11T17:53:24.976620+00:00 and finished 2026-10-11T17:54:01.548038+00:00; runs are parallel, so timings include contention and are indicative only.

Ground truth is author-written labeling with evidence pointers, frozen before any tool ran. It is not independent human review; the same maintainer wrote ShadowScan, the harness and the labels. See the benchmark README for the protocol and its limits.

Tools skipped in this run:

- `cartography`: not runnable by design: AI-relevant modules (anthropic, openai, aws bedrock/sagemaker, gcp vertex) sync live APIs with admin credentials into a running Neo4j server; without Neo4j it exits 1 (ServiceUnavailable) and there is no offline-export ingestion mode
- `power_pwn`: not runnable by design: every discovery path (recon, dump, copilot-studio-hunter, llm-hound) requires a live Microsoft 365 / Power Platform tenant with interactive MSAL authentication or live internet scanning; there is no offline-export mode

## Headline

| Tool | Surfaces declared | Runs | Positives detected (in scope) | Entity TP/FP/TN/FN (in scope) | Entity P / R / F1 (in scope) | In-scope value P / R / F1 | Positives detected (estate-wide) | Estate-wide value recall | Seconds median / max |
|---|---|---|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) (0.1.2) | cloud, code, endpoint, gateway, identity, lowcode, network, runtime, saas | 1 ok | 83/87 | 83/8/42/4 | 91% / 95% / 93% | 92% / 95% / 93% | 83/87 | 95% | 4.06 / 4.06 |
| Snyk Agent Scan (mcp-scan) (0.6.8) | endpoint | 3 ok | 9/19 | 9/0/6/10 | 100% / 47% / 64% | 100% / 47% / 64% | 9/87 | 9% | 0.93 / 1.38 |
| AgentDiscover (2.9.5) | code | 10 ok | 5/6 | 5/0/4/1 | 100% / 83% / 91% | 100% / 35% / 52% | 5/87 | 8% | 2.94 / 3.27 |
| AI-Infra-Guard (4.6.5) | runtime | 1 ok | 2/6 | 2/0/4/4 | 100% / 33% / 50% | 100% / 33% / 50% | 2/87 | 2% | 1.97 / 1.97 |
| SafeDep vet (ai discover) (1.20.0) | code, endpoint | 13 ok | 11/25 | 11/0/10/14 | 100% / 44% / 61% | 100% / 29% / 44% | 11/87 | 12% | 0.17 / 0.22 |
| Numbat (0.2.0) | endpoint | 3 ok | 4/19 | 4/0/6/15 | 100% / 21% / 35% | 100% / 21% / 35% | 4/87 | 4% | 0.22 / 0.23 |
| Agentic Radar (0.14.1) | code | 10 ok | 2/6 | 2/0/4/4 | 100% / 33% / 50% | 100% / 9% / 16% | 2/87 | 2% | 6.0 / 6.86 |
| AgentSight (local sessions) (1.0.34) | endpoint | 3 ok | 1/19 | 1/0/6/18 | 100% / 5% / 10% | 100% / 5% / 10% | 1/87 | 1% | 0.03 / 0.08 |
| Cisco MCP Scanner (4.8.6) | endpoint | 3 ok | 0/19 | 0/0/6/19 | n/a / 0% / n/a | n/a / 0% / n/a | 0/87 | 0% | 8.35 / 12.35 |

In-scope metrics count only the entities and expected facts on the surfaces a tool declares: entity TP/FP/TN/FN are positives detected, negatives flagged, negatives left clean and positives missed among those entities. The estate-wide columns charge every tool for every positive and every expected fact on all nine surfaces. A tool marked incomplete had at least one run that did not complete; see Run status.

## Run status

| Tool | Units run | Statuses | Incomplete or missing units | Commands | Non-zero exits the adapter accepts | Unscored in-scope entities |
|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) | 1 | 1 ok | none | 1 | 0 | 0 |
| Snyk Agent Scan (mcp-scan) | 3 | 3 ok | none | 3 | 0 | 0 |
| AgentDiscover | 10 | 10 ok | none | 30 | 0 | 0 |
| AI-Infra-Guard | 1 | 1 ok | none | 1 | 0 | 0 |
| SafeDep vet (ai discover) | 13 | 13 ok | none | 13 | 0 | 0 |
| Numbat | 3 | 3 ok | none | 3 | 0 | 0 |
| Agentic Radar | 10 | 10 ok | none | 50 | 48 | 0 |
| AgentSight (local sessions) | 3 | 3 ok | none | 3 | 0 | 0 |
| Cisco MCP Scanner | 3 | 3 ok | none | 3 | 0 | 0 |

A run is incomplete when its status is not ok, the adapter reported it incomplete, it recorded an error, or a command timed out or exited with a code the adapter does not declare as success; a code or home unit with no run is missing. Every entity an incomplete or missing run reaches is unscored: its positives count as missed and its negatives earn no true negative, so a failed run never reads as a clean result. Non-zero exits an adapter declares as success are counted here but not treated as failures; check the run's stderr captures before relying on a tool whose commands mostly exit non-zero.

## Attribution

| Tool | Predictions | Tolerated | Attributed | Ambiguous | Unattributed | Outside declared surfaces |
|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) | 124 | 0 | 124 | 0 | 0 | 0 |
| Snyk Agent Scan (mcp-scan) | 18 | 1 | 17 | 0 | 0 | 0 |
| AgentDiscover | 8 | 0 | 8 | 0 | 0 | 0 |
| AI-Infra-Guard | 2 | 0 | 2 | 0 | 0 | 0 |
| SafeDep vet (ai discover) | 39 | 1 | 38 | 0 | 0 | 0 |
| Numbat | 4 | 0 | 4 | 0 | 0 | 0 |
| Agentic Radar | 2 | 0 | 2 | 0 | 0 | 0 |
| AgentSight (local sessions) | 1 | 0 | 1 | 0 | 0 | 0 |
| Cisco MCP Scanner | 0 | 0 | 0 | 0 | 0 | 0 |

A prediction is attributed only to an entity on its own surface that its run can reach (for a per-repository or per-home run, the entities with artifacts in that repository or home tree). Among entities whose anchor appears in the prediction, one that expects the predicted fact wins, then one whose expected or tolerated facts share its category. A prediction still matching several entities goes to the longest anchor, then the first entity id in sort order, and is counted as ambiguous. Tolerated counts predictions dropped by a corpus-level tolerated pair. Unattributed predictions are false positives. Predictions outside the declared surfaces count in the estate-wide numbers only.

## Value-level F1 by surface

| Tool | code (n=23) | identity (n=12) | gateway (n=7) | lowcode (n=10) | saas (n=11) | cloud (n=10) | endpoint (n=19) | network (n=6) | runtime (n=6) |
|---|---|---|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) | 96% (22/1/1) | 92% (12/2/0) | 80% (6/2/1) | 90% (9/1/1) | 87% (10/2/1) | 90% (9/1/1) | 100% (19/0/0) | 100% (6/0/0) | 100% (6/0/0) |
| Snyk Agent Scan (mcp-scan) | out of scope (0/0/23) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | 64% (9/0/10) | out of scope (0/0/6) | out of scope (0/0/6) |
| AgentDiscover | 52% (8/0/15) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | out of scope (0/0/19) | out of scope (0/0/6) | out of scope (0/0/6) |
| AI-Infra-Guard | out of scope (0/0/23) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | out of scope (0/0/19) | out of scope (0/0/6) | 50% (2/0/4) |
| SafeDep vet (ai discover) | 23% (3/0/20) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | 64% (9/0/10) | out of scope (0/0/6) | out of scope (0/0/6) |
| Numbat | out of scope (0/0/23) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | 35% (4/0/15) | out of scope (0/0/6) | out of scope (0/0/6) |
| Agentic Radar | 16% (2/0/21) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | out of scope (0/0/19) | out of scope (0/0/6) | out of scope (0/0/6) |
| AgentSight (local sessions) | out of scope (0/0/23) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | 10% (1/0/18) | out of scope (0/0/6) | out of scope (0/0/6) |
| Cisco MCP Scanner | out of scope (0/0/23) | out of scope (0/0/12) | out of scope (0/0/7) | out of scope (0/0/10) | out of scope (0/0/11) | out of scope (0/0/10) | n/a (0/0/19) | out of scope (0/0/6) | out of scope (0/0/6) |

Cells read F1 (true positives / false positives / false negatives).

## Control and near-miss entities

| Entity | Surface | Class | ShadowScan (Project Nexus) | Snyk Agent Scan (mcp-scan) | AgentDiscover | AI-Infra-Guard | SafeDep vet (ai discover) | Numbat | Agentic Radar | AgentSight (local sessions) | Cisco MCP Scanner |
|---|---|---|---|---|---|---|---|---|---|---|---|
| code.repo-wms-core | code | control | clean | out of scope | clean | out of scope | clean | out of scope | clean | out of scope | out of scope |
| code.repo-site | code | control | clean | out of scope | clean | out of scope | clean | out of scope | clean | out of scope | out of scope |
| code.repo-canbus-fw | code | nearmiss | clean | out of scope | clean | out of scope | clean | out of scope | clean | out of scope | out of scope |
| code.repo-ua-parser | code | nearmiss | clean | out of scope | clean | out of scope | clean | out of scope | clean | out of scope | out of scope |
| identity.okta-gemini-exchange | identity | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.entra-payroll-sso | identity | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.entra-aix-billing-sync | identity | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.google-expense | identity | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.auth0-driver-portal | identity | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.auth0-mcp2515 | identity | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| identity.jwt-human-control | identity | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| gateway.egress-wiki-sync | gateway | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| gateway.egress-helpdesk-browser | gateway | control | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| gateway.otel-billing-cron | gateway | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| gateway.egress-run-audit | gateway | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| gateway.egress-treasury-ticker | gateway | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.flow-nightly-pod-copy | lowcode | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.snow-copilot-cleanup | lowcode | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.n8n-backup-sheets | lowcode | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.zap-invoice-drive | lowcode | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.zap-ai-newsletter | lowcode | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| lowcode.workato-gemini-exchange | lowcode | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.slack-freight-webhook | saas | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.teams-mistral-route | saas | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.github-renovate | saas | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.github-dataai-export | saas | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.atlassian-timesheets | saas | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.notion-jira-sync | saas | control | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.zoom-whiteboard-sync | saas | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| saas.generic-gemini-exchange | saas | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.lambda-warehouse-label | cloud | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.azure-storage-docs | cloud | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.k8s-fleet-portal-nginx | cloud | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.lambda-ai-cost-reporter | cloud | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.k8s-sagemaker-exporter | cloud | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| cloud.gcp-gemini-settlement | cloud | nearmiss | flagged | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| endpoint.ublock-ext-dl02 | endpoint | control | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| endpoint.ebpf-backup-sync | endpoint | control | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| endpoint.htop-config-dl01 | endpoint | control | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| endpoint.gemini-wallet-ext-dl02 | endpoint | nearmiss | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| endpoint.cursorstats-dl01 | endpoint | nearmiss | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| endpoint.claude-backup-bak-dl01 | endpoint | nearmiss | clean | clean | out of scope | out of scope | clean | clean | out of scope | clean | clean |
| network.corp-web-and-github | network | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| network.slack-generic-dns | network | control | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| network.gemini-crypto-exchange | network | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| network.claude-monet-exhibit | network | nearmiss | clean | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope | out of scope |
| runtime.nginx-control | runtime | control | clean | out of scope | out of scope | clean | out of scope | out of scope | out of scope | out of scope | out of scope |
| runtime.ollama-list-control | runtime | control | clean | out of scope | out of scope | clean | out of scope | out of scope | out of scope | out of scope | out of scope |
| runtime.claudette-backup-nearmiss | runtime | nearmiss | clean | out of scope | out of scope | clean | out of scope | out of scope | out of scope | out of scope | out of scope |
| runtime.train-model-nearmiss | runtime | nearmiss | clean | out of scope | out of scope | clean | out of scope | out of scope | out of scope | out of scope | out of scope |

An unscored negative was reached by an incomplete or missing run and is not a true negative.

## Registry reconciliation (shadow layer)

| Tool | Detected positives with a verdict | Correct verdicts |
|---|---|---|
| ShadowScan (Project Nexus) | 83 | 83 |
| Snyk Agent Scan (mcp-scan) | no registry reconciliation | n/a |
| AgentDiscover | no registry reconciliation | n/a |
| AI-Infra-Guard | no registry reconciliation | n/a |
| SafeDep vet (ai discover) | no registry reconciliation | n/a |
| Numbat | no registry reconciliation | n/a |
| Agentic Radar | no registry reconciliation | n/a |
| AgentSight (local sessions) | no registry reconciliation | n/a |
| Cisco MCP Scanner | no registry reconciliation | n/a |

A verdict is correct when every finding attributed to the entity carries the expected reconciliation: registered entities read registered, unregistered positives read shadow.

## Misses and extra findings by tool

### ShadowScan (Project Nexus)

Missed in-scope positives: gateway.egress-yard-planner, lowcode.n8n-dock-manifest-qa, saas.slack-wudpecker, cloud.k8s-eta-vllm

### Snyk Agent Scan (mcp-scan)

Missed in-scope positives: endpoint.ollama-store-dl01, endpoint.continue-dl02, endpoint.copilot-ext-dl02, endpoint.claude-ext-dl02, endpoint.claude-desktop-wl03, endpoint.cline-wl03, endpoint.lmstudio-store-wl03, endpoint.mcp-freight-docs-poisoned, endpoint.ollama-build-runner-3, endpoint.ebpf-openai-egress

### AgentDiscover

Missed in-scope positives: code.repo-infra

### AI-Infra-Guard

Missed in-scope positives: runtime.claude-code-dana, runtime.mcp-server-github-dana, runtime.aider-marcus, runtime.ollama-serve-priya

### SafeDep vet (ai discover)

Missed in-scope positives: code.repo-freight-crew, code.repo-support-bot-ts, code.repo-infra, code.repo-n8n-flows, endpoint.claude-desktop-dl01, endpoint.ollama-store-dl01, endpoint.copilot-ext-dl02, endpoint.claude-ext-dl02, endpoint.claude-desktop-wl03, endpoint.cline-wl03, endpoint.lmstudio-store-wl03, endpoint.mcp-freight-docs-poisoned, endpoint.ollama-build-runner-3, endpoint.ebpf-openai-egress

### Numbat

Missed in-scope positives: endpoint.windsurf-dl01, endpoint.claude-desktop-dl01, endpoint.ollama-store-dl01, endpoint.continue-dl02, endpoint.copilot-ext-dl02, endpoint.claude-ext-dl02, endpoint.claude-desktop-wl03, endpoint.amazon-q-wl03, endpoint.cline-wl03, endpoint.lmstudio-store-wl03, endpoint.mcp-github, endpoint.mcp-adatum-freight, endpoint.mcp-freight-docs-poisoned, endpoint.ollama-build-runner-3, endpoint.ebpf-openai-egress

### Agentic Radar

Missed in-scope positives: code.repo-freight-crew, code.repo-support-bot-ts, code.repo-infra, code.repo-ops-scripts

### AgentSight (local sessions)

Missed in-scope positives: endpoint.cursor-dl01, endpoint.windsurf-dl01, endpoint.claude-desktop-dl01, endpoint.ollama-store-dl01, endpoint.codex-dl02, endpoint.gemini-cli-dl02, endpoint.continue-dl02, endpoint.copilot-ext-dl02, endpoint.claude-ext-dl02, endpoint.claude-desktop-wl03, endpoint.amazon-q-wl03, endpoint.cline-wl03, endpoint.lmstudio-store-wl03, endpoint.mcp-github, endpoint.mcp-adatum-freight, endpoint.mcp-freight-docs-poisoned, endpoint.ollama-build-runner-3, endpoint.ebpf-openai-egress

### Cisco MCP Scanner

Missed in-scope positives: endpoint.claude-code-dl01, endpoint.cursor-dl01, endpoint.windsurf-dl01, endpoint.claude-desktop-dl01, endpoint.ollama-store-dl01, endpoint.codex-dl02, endpoint.gemini-cli-dl02, endpoint.continue-dl02, endpoint.copilot-ext-dl02, endpoint.claude-ext-dl02, endpoint.claude-desktop-wl03, endpoint.amazon-q-wl03, endpoint.cline-wl03, endpoint.lmstudio-store-wl03, endpoint.mcp-github, endpoint.mcp-adatum-freight, endpoint.mcp-freight-docs-poisoned, endpoint.ollama-build-runner-3, endpoint.ebpf-openai-egress

