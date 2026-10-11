# Nine-surface shadow AI agent discovery benchmark

A standardized, tool-neutral benchmark that asks one question on every surface
where shadow AI agents leave evidence: *given what an operator can actually
collect from this surface, which AI agents and which plain AI uses are present,
and can a discovery tool find them without flagging the things that merely
sound like AI?*

It covers nine surfaces: code repositories, identity providers, LLM gateways,
low-code platforms, SaaS workspaces, cloud accounts (including Kubernetes),
developer endpoints, the network, and running processes. Every case carries
entity-level ground truth with a label and the evidence behind it, plus the
decoys a tool must leave alone, so the benchmark measures true positives, false
positives, false negatives and true negatives per entity, per surface, per
tool, and reports precision, recall, F1, specificity, balanced accuracy, MCC,
agent-tier recall and false-alarm rate, estate-wide recall, and paired
comparisons with confidence intervals.

The harness is `tools/nine_surface/` ([its README](../../tools/nine_surface/README.md)
has the commands). This directory holds the corpus, the committed results and
this description. Nothing here is a release artifact.

> **Read this first.** The corpus is generated from rubrics the ShadowScan
> maintainers wrote, in ShadowScan's own repository, and the same author wrote
> the adapters for every tool. The code surface uses real public repositories,
> but their labels are session-labeled evidence, not independent review. Eight
> surfaces use synthetic exports because no public source of real tenant,
> gateway, endpoint or process data exists. The results show how each tool
> behaves on these inputs. They do not estimate field precision or recall, they
> are not an independent evaluation, and any ShadowScan lead is suspect until
> someone without a stake reruns the benchmark, ideally with their own seed,
> their own families, and their own labels. Everything needed to do that is
> committed and hashed.

## What is measured

A case is one input a tool is pointed at: an identity-provider export, a
gateway log window, a low-code platform export, a SaaS admin export, a cloud
account's CLI outputs or a Kubernetes workload list, a developer's home
directory, a workstation's network window or a set of listening services, a
host's process table, or a repository checkout. Each case lists:

* **expected entities**, each with a key, a label (`agent` or `llm`) and the
  evidence that justifies it;
* **tolerated keys**: supporting records a tool may report without penalty
  (a client's parent directory, an agent's execution role, a pending install
  request);
* **decoys**: records labeled `none` whose keys form the true-negative
  universe (service accounts without AI, monitoring *agents*, Minecraft
  *Bedrock* servers, apps named *copilot*, classic chatbots, plain workloads).

Labels: `agent` is an autonomous or tool-using AI agent or an agent
integration (a configured MCP server, Copilot Studio agent, Bedrock agent,
coding-agent CLI, agent framework process); `llm` is AI use without agent
evidence (a chat SaaS app, a model server, a single-completion caller, a GPT
step in a flow); `none` is no AI. Exact rubrics per surface are the module
docstrings under `tools/nine_surface/families/`.

Entity keys are tool-neutral identifiers from the platform's own data: the
Okta app id or Entra `appId`, the gateway key alias or principal ARN, the
Power Platform bot or flow id, the n8n workflow id, the Slack app id or GitHub
App slug, the AWS ARN or `namespace/Kind/name`, the artifact path under the
home directory, the client address or `ip:port`, the pid, and for code the
`<category>:<value>` facts of the [code-surface benchmark](../shadow-ai-discovery/README.md).

### Surfaces, modalities and inputs

| Surface | Modality | What the tool is pointed at | Cases | Expected entities | Decoys |
|---|---|---|---|---|---|
| code | checkout | 26 public repositories pinned by commit (16 positive, 4 control, 6 near-miss) | 26 | 109 facts | 0 (controls and near-misses: anything reported is a false positive) |
| identity | okta-export | `GET /api/v1/apps` plus each app's grants and tokens | 20 | | |
| identity | entra-export | Graph `servicePrincipals`, `applications`, `oauth2PermissionGrants`, `appRoleAssignments` | 20 | 96 | 159 |
| gateway | litellm-export | LiteLLM `/spend/logs` rows | 20 | | |
| gateway | bedrock-export | Bedrock model invocation logs (CloudWatch) | 20 | 124 | 0 (every caller uses a model; the test is agent tier) |
| lowcode | powerplatform-export | Power Platform environments, flows, apps, Copilot Studio bots and components | 20 | | |
| lowcode | n8n-export | `GET /api/v1/workflows` | 20 | 78 | 118 |
| saas | slack-export | `admin.apps.approved.list`, `admin.apps.requests.list`, `users.list`, `team.info` | 20 | | |
| saas | github-export | `GET /orgs/{org}/installations` | 20 | 88 | 110 |
| cloud | aws-export | AWS CLI JSON: STS, Bedrock Agents, AgentCore, Lambda, SageMaker, IAM | 20 | | |
| cloud | k8s-export | `kubectl get deploy,sts,ds -A -o json` | 20 | 77 | 133 |
| endpoint | home | a developer home directory, given to the tool as `HOME` | 40 | 24 | 0 (negative homes: anything reported is a false positive) |
| network | passive | Zeek `conn`, `ssl`, `dns`, `http` logs of one workstation's window | 20 | | |
| network | active | loopback services served inside the tool's network namespace | 20 | 44 | 50 |
| runtime | snapshot | osquery process rows and osqueryd result-log lines | 20 | | |
| runtime | live | inert processes spawned under the recorded names and command lines | 20 | 98 | 165 |

346 cases, 738 expected entities, 735 decoys. Within a surface the second row
of each pair carries the surface's totals.

Two modalities make tools that only work live measurable offline. **Active
network** cases start mock services on loopback inside the tool's network
namespace (`tools/nine_surface/mockserv.py`), each answering the routes a
fingerprinting scanner probes the way the real product does: Ollama's
`/api/tags`, vLLM's `/v1/models`, Open WebUI's `/api/config`, an MCP server's
`initialize`, an OpenClaw gateway's `/health`, and decoys such as a Grafana
login page, a Jenkins banner, a Datadog Agent Manager page and a Minecraft
*Bedrock* panel. **Live runtime** cases spawn an inert static binary under each
recorded process name with the recorded command line, inside the tool's PID
namespace, so a tool that reads `/proc` sees exactly the processes a snapshot
describes. Reported pids are translated back to the corpus's process keys.

### Platform-native inputs and conversions

Inputs are the platforms' own shapes, so no tool is handed another tool's
format. Where a tool reads its own offline format, its adapter converts and the
conversion is documented in the adapter docstring. ShadowScan's adapter embeds
Okta grants and tokens into the app list, concatenates the Graph arrays with a
role-id map, concatenates the Power Platform and Slack collections, and re-keys
the AWS CLI outputs into its dumped record kinds; IAM roles are not converted
(its offline IAM record needs pre-analysed policy fields), so the IAM decoy
tests nothing for ShadowScan. Everything else is read unchanged.

## Metrics

Per tool, per surface and per modality:

* **Entity level.** A reported key matches an expected or decoy key when it is
  equal or, for home-directory artifacts, when one path is a parent directory
  of the other. TP, FP, FN, TN; precision, recall and specificity with Wilson
  95% intervals; F1 with a 2,000-sample case bootstrap interval. A reported key
  that matches nothing expected or tolerated is a false positive; one that hits
  a decoy also counts against specificity.
* **Agent tier.** Recall on expected `agent` entities counting only reports
  labeled `agent`; the false-alarm rate on expected `llm` entities and decoys
  that a tool labeled `agent`. A tool that cannot tell agents from plain AI
  use reports `ai` and earns no agent-tier credit.
* **Case level.** Detected (any true or false positive) against the case
  label: recall, specificity, balanced accuracy, MCC.
* **Estate recall.** Expected entities found over all expected entities in
  the corpus, charging a tool for the surfaces it does not cover; **coverage**
  is the number of surfaces it ran on.
* **Errors and incompleteness.** A crash, timeout or unreadable output is an
  `error`: every expected entity counts as missed and no decoy is credited; it
  is never a clean negative. A run the tool itself marks incomplete is scored
  on what it reported and counted separately.
* **Paired comparison.** Exact McNemar test on case-level correctness against
  the reference tool over the cases both ran.
* **Timing.** Median, p90 and maximum seconds per case (indicative only; runs
  are parallel).

## How the corpus is built, and how to check it

`python -m tools.nine_surface generate --seed 20261011 --per-surface 40` writes
`corpus.json`. Each export-style case draws entity families by quota (45%
agent, 15% plain AI, 40% decoy, at least one decoy per export), redraws
collisions, and renders the platform's files. Endpoint and passive-network
cases reuse the 20 endpoint and 17 network families the earlier head-to-head
benchmark pre-registered in `tools/benchmark/`, adding the artifact or client
key each family plants. Code cases come from the pinned
[code-surface corpus](../shadow-ai-discovery/corpus.json), whose facts and
tolerated facts are carried over; `provider:*` facts are `llm`, all others
`agent`.

The corpus records its seed and a SHA-256 over the generator sources (including
the code corpus). `python -m tools.nine_surface verify --corpus corpus.json
--regenerate` rebuilds it and compares byte for byte, so anyone can confirm
that the committed inputs are exactly what the committed code produces, and
can generate a fresh corpus at another seed to test for overfitting to this
one. Every result file names the corpus hash, the generator digest, the
platform and each tool's version or commit.

### Bias controls

* The rubrics, families, generator, adapters and scoring rules were written
  and committed before the scored run. The adapters were calibrated on probe
  inputs and a 4-case-per-surface smoke corpus, never on the scored corpus.
  Calibration changes are recorded in each adapter's docstring.
* Decoys are drawn from the confusions real tools make: service identities
  without AI, infrastructure *agents*, *Bedrock* game servers, *MCP* (Minecraft
  Coder Pack, Microsoft Cloud Partner), *copilot* seat reports, *Gemini*
  exchange clients, embedding batches that look like agent loops, classic
  chatbots, flows and workflows whose names mention AI.
* Every tool runs with no network, no inherited credentials, a case-local
  `HOME`, and (except live-runtime and active-network cases) no view of host
  processes. No tool is given an allowlist, an inventory or a known-agent
  list.
* Tools are scored only on surfaces and modalities they declare; estate recall
  shows the cost of the surfaces they do not cover without penalizing their
  in-scope precision.
* Tool output is kept verbatim (`raw/`) beside the normalized entities, so the
  mapping can be audited and re-applied.
* A tool's own notion of a finding is used: no confidence threshold is imposed
  on top of what the tool reports at its defaults.

### Known limits

* **Synthetic, author-written data on eight surfaces.** Real tenants are
  messier, larger and have more kinds of records. The families encode the
  author's view of what evidence suffices; a tool built on a different
  theory of evidence (for example one that inventories every non-human
  identity) is penalized by the rubric, and the report says where.
* **Conflict of interest.** See the note at the top. The code surface's
  labels inherit the code-surface benchmark's caveats.
* **Live tools cannot all be exercised.** Cartography (needs Neo4j and live
  cloud APIs), Microsoft's Copilot Studio Kit Agent Inventory (a Power
  Platform solution), Google's k8s-aibom (an in-cluster controller with no
  manifest mode) and AgentSight (eBPF uprobes on live TLS libraries) have no
  offline entry point; they are listed as not run with the reason. A live
  replay profile (mock REST APIs behind the platforms' real endpoints, or a
  kind cluster for k8s-aibom) is the designed extension and is not
  implemented here.
* **Mock services approximate real responses.** They reproduce banners,
  version endpoints and product names, not full applications. A fingerprint
  that depends on behaviour the mocks do not reproduce will miss; a
  fingerprint that fires on generic JSON error bodies will false-positive
  exactly as it would on the real product.
* **The gateway surface has no decoys.** Every caller in an LLM gateway log
  uses a model, so the gateway test is agent tier only.
* **Small per-surface samples.** Twenty cases per modality give wide
  intervals; the report prints them. Regenerate at a larger `--per-surface`
  for narrower ones.

### The 2026-10-11 run, in brief

Nine tools ran on all 346 cases with no crashes or timeouts
([`results/2026-10-11/REPORT.md`](results/2026-10-11/REPORT.md)). Read these
with the caveats above: the rubrics are the author's, and ShadowScan is the
only tool whose maintainer also wrote the corpus.

* ShadowScan was the only tool to run on every surface (estate recall 84%,
  in-scope entity F1 83%). Its weak points are exactly where the rubric and
  its design disagree: it inventories service identities with admin scopes
  and non-AI workspace bots as findings, so identity specificity was 57% and
  SaaS specificity 33%; it reports classic topic-only Copilot Studio bots as
  agents; it labelled a `gemini` crypto-exchange CLI as Gemini CLI; it missed
  Entra Agent ID objects, Langflow and OpenClaw images on Kubernetes, and
  scripts whose only evidence is a `--model` flag. Twenty live-runtime scans
  and seven code scans were self-declared incomplete (a container PID
  namespace; oversized files), as its fail-closed rule requires.
* AI-Infra-Guard identified 26 of 32 AI services on loopback with no false
  positives on the decoys after they answered unknown paths with HTML as the
  real products do; it labels vLLM, TGI and LiteLLM as *AI-Agent-Config*
  because their JSON 404 bodies satisfy that fingerprint, and it missed
  Flowise.
* On developer homes, Fleet's table found the most artifacts of the
  endpoint-only tools (10 of 24), Snyk Agent Scan 7 with no false positives,
  Numbat 3 (it keys on configuration directories and misses VS Code and
  OpenClaw), Cisco MCP Scanner 1 (its Linux path table covers Cursor,
  Windsurf and VS Code only). SafeDep vet reported plain VS Code as a coding
  agent on every home that had a `.vscode` directory (39 false positives).
* On running processes, Microsoft's `agent-discovery` and Fleet's table found
  MCP servers and framework runs (6 and 5 of 48 expected) and nothing else;
  neither recognises coding-agent CLIs or model servers from their command
  lines.
* On code, ShadowScan reached fact-level F1 94% on the 26 pinned repositories;
  AgentDiscover 13% (247 false-positive facts), vet 15% and `agent-discovery`
  9%, each limited to configuration files.

## Tools

| Tool | Version benchmarked | Surfaces it ran on | How it is run |
|---|---|---|---|
| ShadowScan (Project Nexus) | this checkout | all nine | one offline connector per modality (see the adapter docstring); `endpoint.inventory` on the home, `runtime.processes` on `/proc` for live cases |
| Snyk Agent Scan | 0.6.8 | endpoint | `snyk-agent-scan inspect --json` with `HOME` set to the case, consent prompts declined (no server started, nothing uploaded) |
| Cisco MCP Scanner | 4.8.6 | endpoint | `mcp-scanner known-configs --analyzers yara`; servers it enumerates from a config count, servers that cannot start offline do not |
| Microsoft Agent Governance Toolkit, `agent-discovery` | 5.0.0 | code, endpoint, runtime (live) | `scan -s config` on the repository or home; `scan -s process` in the PID namespace; its own process is ignored |
| AgentDiscover Scanner | 2.9.5 | code, endpoint | `scan-all --skip-layers 2,3,4,5 --format json` |
| Numbat (Perplexity) | 77ece3a (2026-10-09) | endpoint | `numbat agents --format json` with `HOME` set to the case; its unit is the client's configuration directory |
| SafeDep vet | v1.20.0 | code, endpoint | `vet ai discover --scope project` / `--scope system` |
| AI-Infra-Guard (Tencent) | v4.6.5 (d9f3aa4) | network (active) | `ai-infra-guard scan -t ip:port ...` with its fingerprint files offline |
| Fleet `ai_tools` table | fleetdm/fleet cf1217b (2026-10-11) | endpoint, runtime (live) | the table's `Generate` function compiled into a small Go program (`fleet-ai-tools`), no osquery daemon needed; rows outside the case home are dropped |
| Cartography, Copilot Studio Kit, k8s-aibom, AgentSight | — | not run | no offline entry point; see Known limits |

Each adapter's docstring records the version, the exact command and the
output-to-entity mapping. `install_tools.sh` in the harness directory
reproduces the installations.

## Results

Committed runs live under `results/<date>/` with `manifest.json` (corpus hash,
generator digest, platform, tool versions), one `<tool>.jsonl` of normalized
rows, `metrics.json` and `REPORT.md`. Raw tool output is not committed. The
newest `REPORT.md` holds the measured numbers; read them with the caveats
above.
