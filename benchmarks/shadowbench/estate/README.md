# ShadowBench — shadow AI agent discovery estate benchmark

One question, asked across every surface at once: given a realistic
organization's artifacts, which discovery tools find the AI agents and AI
usage hiding in them, how precisely, and at what false-positive cost?

The corpus models **Vantor Logistics**, a fictional organization, as a
single estate of vendor-format artifacts across all nine ShadowScan
surfaces: code repositories, identity-provider exports, gateway logs,
low-code platform exports, SaaS app inventories, cloud inventories,
materialized endpoint home trees plus offline endpoint exports, network
logs, and runtime process exports. Everything needed to re-run it is in
this directory and `tools/shadowbench/estate/`; nothing requires credentials
or network access beyond installing the tools under test.

**This benchmark is not independent.** The same maintainer wrote
ShadowScan, the harness, the artifacts and the labels, with format
knowledge derived from ShadowScan's own documentation. Section
[Bias and limits](#bias-and-limits) lists what that means and what was done
about it. Treat the results as offline evidence about these inputs, never
as measured field precision or recall, and never as a second-person audit.

## Corpus

137 labeled **entities** (ground truth in [`corpus.json`](corpus.json),
artifacts under [`artifacts/`](artifacts/)):

| Class | Count | Meaning |
|---|---|---|
| positive | 87 | a genuine AI agent or AI usage per the artifact's vendor semantics |
| control | 27 | clearly non-AI; any attributed in-scope finding is a false positive |
| near-miss | 23 | AI-adjacent vocabulary or shape without AI technology (crypto-exchange `api.gemini.com`, an MCP2515 CAN-bus library, a "Gemini Wallet" extension, `claudette-backup`); flagging it is a false positive |

Four positives are **registered** in the supplied agent registry
([`artifacts/registry/agents.yaml`](artifacts/registry/agents.yaml)): a Bedrock
agent, a Copilot Studio bot, a GitHub App AI reviewer and Claude Code on
one laptop. Discovering them is still expected; classifying them as shadow
is not.

Each entity carries `<category>:<value>` facts from the tool-neutral
taxonomy in `tools/shadowbench/estate/taxonomy.py` (the code surface reuses
the code-surface benchmark's eight categories; the other surfaces add
`oauth-app`, `service-identity`, `token`, `bot-app`, `lowcode-agent`,
`cloud-ai`, `ai-client`, `model-store`, `gateway-caller`,
`ai-service-contact`, `agent-process`), evidence pointers, and **anchors**:
unique tokens embedded in the artifacts (app ids, ARNs, server names,
client IPs). A tool's prediction is attributed to the entity whose anchor
appears in the prediction's own identifiers (longest anchor wins); a
prediction from a per-repository or per-home run with no anchor falls back
to the unit's entity with the matching fact. Unattributed in-scope
predictions are charged as false positives. `<category>:generic` matches
one expected fact of its category. Tolerated facts (per entity, plus the
corpus-level pairs under `tolerated`) are dropped before scoring.

The corpus deliberately includes, in both directions:

- positives that may exceed documented detection: a self-hosted
  text-generation-inference caller in an egress log, an n8n flow calling a
  self-hosted vLLM over plain `httpRequest`, a k8s vLLM workload with no
  marker image or env names, a Wudpecker Slack notetaker, Defender- and
  CrowdStrike-format process rows;
- negatives that discovery tools, ShadowScan included, are known to
  over-flag: a Notion non-AI sync bot, a crypto-exchange Gemini OIDC app
  and Cloud Run service, a ServiceNow flow with an AI product name, a
  Chrome caller at the confidence threshold, hosted-agent `GET /runs`
  near-misses.

## Protocol

1. **Authoring.** Nine authors wrote each surface's artifacts and labels
   together, from vendor semantics. Artifacts were verified to parse
   cleanly in ShadowScan's offline loaders (completeness only: exit 0, no
   warnings); labels were never changed because a tool missed or flagged
   an entity.
2. **Additions.** Agent session transcripts were added to two home trees
   (`.claude/projects`, `.cursor` agent transcripts, `.codex/sessions`) so
   installed agents carry the at-rest artifacts a real endpoint would
   have; `artifacts/registry/` and `artifacts/services/` were added.
3. **Label-completeness audit.** Every runnable tool ran once; every
   prediction attributed to no entity was audited. Outcomes: adapter
   normalization fixes, one secondary anchor, and one corpus-level
   tolerated pair (a bare "VS Code is present" client row; the corpus
   models the AI extension inside the editor as the entity, not the
   editor). Recorded in `corpus.json` `metadata.errata`. No entity labels
   changed.
4. **Freeze.** [`FREEZE.json`](FREEZE.json) pins the SHA-256 of all 139
   corpus files; `python -m tools.shadowbench.estate verify-freeze` checks
   drift. The published run was produced after the freeze.

**Erratum (integration, 2026-10-12).** The repository's `.vscode/` ignore
rule kept one frozen file out of #194's commits:
`artifacts/home/dev-laptop-02/marcus/.vscode/extensions/github.copilot-1.388.0/package.json`,
the only artifact of `endpoint.copilot-ext-dl02`. Its original bytes were
lost with the authoring session, so a minimal extension manifest replaces
it and `FREEZE.json` records the replacement's digest. The entity's
evidence is the extension's directory name, which is unchanged; a tool that
reads the manifest itself may behave differently on a re-run than in the
2026-10-11 run. `.gitignore` now re-includes `.vscode/` under `artifacts/`,
and `tests/unit/test_shadowbench_estate.py` fails if any frozen file is not
tracked.

## Execution and isolation

Runs use the code-surface benchmark's scrubbed environment: a rebuilt
environment with a dead proxy (`http://127.0.0.1:9`), a private `HOME` and
`TMPDIR` per run, telemetry opt-outs, and process-group kills on timeout.
The harness is not a filesystem or network sandbox; run third-party tools
only inside an externally isolated disposable machine with no credentials.

**The benchmark never executes corpus content.** Tools that enumerate MCP
servers by launching them run with that behavior disabled or inert:
Snyk Agent Scan runs in `inspect` mode with stdin at `/dev/null`, so the
per-server consent prompt auto-denies and every server is still
inventoried; Cisco MCP Scanner is allowed to attempt stdio launches, but
`npx` is off the scrubbed `PATH` and the proxy is dead, so no
corpus-specified package can resolve or run — its zero score on
configuration inventory is a measured consequence of its
connection-required design, not a harness failure.

The network live-sim mirrors the estate's two running model servers
(`artifacts/services/services.json`) as loopback mock HTTP services via
`tools/shadowbench/estate/simhost.py`, so live network fingerprinting tools
have something real to probe without anything leaving the machine.

## Tools

| Tool | Version | Mode in this benchmark | Surfaces |
|---|---|---|---|
| ShadowScan (Project Nexus) | 0.1.2 | one offline scan, all connectors, registry supplied | all nine |
| Snyk Agent Scan (mcp-scan) | 0.6.8 | `inspect --json`, consent auto-denied | endpoint |
| Numbat | 0.2.0 | `agents --format json` + `scan --emit all` per home tree | endpoint |
| AgentSight | 1.0.34 | local-session reports over `$HOME` (no eBPF) | endpoint |
| Cisco MCP Scanner | 4.8.6 | `--analyzers yara` known-configs + explicit Claude configs | endpoint |
| SafeDep vet | 1.20.0 | `ai discover` per repo and per home tree | code, endpoint |
| Agentic Radar | 0.14.1 | five framework scans per repo | code |
| AgentDiscover | 2.9.5 | `scan --format sarif` + deps + MCP policy per repo | code |
| AI-Infra-Guard | 4.6.5 | `scan --target` against the loopback live-sim | runtime |
| power-pwn | 6.0.0 | **not runnable by design** | — |
| Cartography | 0.143.0 | **not runnable by design** | — |

Exclusion evidence, recorded during provisioning on this machine:

- **power-pwn 6.0.0**: every discovery path (`recon`, `dump`,
  `copilot-studio-hunter`, `llm-hound`) requires a live Microsoft 365 /
  Power Platform tenant with interactive MSAL authentication or live
  internet scanning; there is no offline-export ingestion mode.
- **Cartography 0.143.0**: the AI-relevant modules (anthropic, openai, aws
  bedrock/sagemaker, gcp vertex) sync live APIs with admin credentials
  into a running Neo4j server; without Neo4j it exits 1
  (`ServiceUnavailable`); there is no offline-export ingestion mode.
- **AgentSight eBPF capture** (its primary runtime mode) is blocked in
  this container: fentry/fexit BPF program loads return `EPERM` on this
  kernel while kprobe and ringbuf programs load fine; only its
  local-session mode runs here, so its runtime surface stays out of scope.

Adapters live in `tools/shadowbench/estate/adapters/`; the registry there is
separate from the code-surface benchmark's registry on purpose. For the
code surface, vet, Agentic Radar and AgentDiscover run through the exact
commands and normalization of `tools/discovery_benchmark`, so their code
results are directly comparable with the code-surface benchmark's.

## Scoring

- **Entity level** — a positive is detected when any attributed in-scope
  prediction matches an expected fact; a control or near-miss is flagged
  by any attributed in-scope prediction. This yields TP / FP / TN / FN,
  precision, recall and F1 over entities.
- **Value level** — exact facts, micro-averaged, with per-surface
  breakdowns. *In-scope* counts only a tool's declared surfaces; the
  *estate-wide* number charges every tool for every expected fact on all
  nine surfaces — the honest cost of partial surface coverage.
- **Shadow layer** — for tools that reconcile against the registry:
  detected registered entities should read registered, detected
  unregistered positives should read shadow.
- Facts a tool reports outside the taxonomy are ignored, never penalized.
  Timings are indicative only (runs are parallel).

## Results

Committed under [`results/2026-10-11/`](results/2026-10-11/): the scrubbed
`runs.json` (per-unit statuses, commands and predictions), `metrics.json`,
the rendered [`REPORT.md`](results/2026-10-11/REPORT.md), the scrubbed
`tools.json`. Headline (entity detection on declared surfaces / in-scope
value F1 / estate-wide value recall):

| Tool | Detected | In-scope value F1 | Estate-wide recall |
|---|---|---|---|
| ShadowScan 0.1.2 | 83/87 | 93% | 95% |
| Snyk Agent Scan 0.6.8 | 9/87 | 64% | 9% |
| AgentDiscover 2.9.5 | 5/87 | 52% | 8% |
| AI-Infra-Guard 4.6.5 | 2/87 | 50% | 2% |
| SafeDep vet 1.20.0 | 11/87 | 43% | 12% |
| Numbat 0.2.0 | 4/87 | 35% | 4% |
| Agentic Radar 0.14.1 | 2/87 | 16% | 2% |
| AgentSight 1.0.34 | 1/87 | 10% | 1% |
| Cisco MCP Scanner 4.8.6 | 0/87 | n/a | 0% |

ShadowScan's four misses are the hard positives listed above; its eight
flagged negatives are deliberate over-flag traps (two controls, six
near-misses). Its registry layer classified all 83 detected positives
correctly (79 shadow, 4 registered). Every other tool covers one or two
surfaces and flagged no control or near-miss in this run — partly real
precision, partly surface coverage: most traps live on surfaces only
ShadowScan reads. The strongest third-party results are Snyk Agent Scan's
and vet's endpoint inventories. See the control and near-miss table in the
report for the full grid.

## Reproduce

```
python -m tools.shadowbench.estate validate
python -m tools.shadowbench.estate verify-freeze
python -m tools.shadowbench.estate run \
    --tools /srv/estate/tools.json --out /srv/estate/runs --workers 4
python -m tools.shadowbench.estate score \
    --runs /srv/estate/runs/runs.json --out metrics.json
python -m tools.shadowbench.estate report --metrics metrics.json --out REPORT.md
```

`tools.json` maps tool ids to installed binaries
(`results/2026-10-11/tools.json` shows the shape and the pinned versions
used; AI-Infra-Guard also needs its `fps` and `vul` data directories).
Install the versions from the results' `tool_versions` for a faithful
reproduction.

## Bias and limits

- **No independent review.** One maintainer wrote the scanner, the
  harness, the artifacts and the labels. Files under `archive/reviews/`
  and green CI are not a second person.
- **Format selection favors ShadowScan.** The artifact formats are the
  offline export formats ShadowScan parses; tools whose native modality is
  a live API (power-pwn, Cartography) or a kernel (AgentSight's eBPF)
  cannot show their strength against an offline corpus. The per-surface
  tables and the exclusion notes above are the honest reading, not the
  single headline number.
- **Trigger knowledge.** Authors knew the documented detection triggers
  of ShadowScan and, to a lesser extent, of the other tools. Mitigations:
  hard positives beyond documented triggers, negatives ShadowScan itself
  over-flags (verified: it flags eight), per-entity rationale, and all
  raw outputs committed.
- **One estate, one snapshot.** 137 entities authored by one process on
  one date; the corpus cannot measure field base rates, scale behavior, or
  live-collection reliability.
- **Author-written corpora cannot establish production precision.** See
  `docs/evaluation.md` for what ShadowScan accepts as evidence.
