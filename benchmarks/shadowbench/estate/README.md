# ShadowBench — shadow AI agent discovery estate benchmark

One question, asked across every surface at once: given a realistic
organization's artifacts, which discovery tools find the AI agents and AI
usage hiding in them, how precisely, and at what false-positive cost?

The corpus models **Adatum Logistics**, a fictional organization, as a
single estate of vendor-format artifacts across all nine ShadowScan
surfaces: code repositories, identity-provider exports, gateway logs,
low-code platform exports, SaaS app inventories, cloud inventories,
materialized endpoint home trees plus offline endpoint exports, network
logs, and runtime process exports. Everything needed to re-run it is in
this directory and [`tools/shadowbench/estate/`](../../../tools/shadowbench/estate/),
which reuses parts of
[`tools/discovery_benchmark/`](../../../tools/discovery_benchmark/README.md).
Nothing requires credentials or network access beyond installing the tools
under test.

**This benchmark is not independent.** The same maintainer wrote
ShadowScan, the harness, the artifacts and the labels, with format
knowledge derived from ShadowScan's own documentation. Section
[Bias and limits](#bias-and-limits) lists what that means and what was done
about it. Treat the results as offline evidence about these inputs, never
as measured field precision or recall, never as a verdict on any vendor's
product, and never as a second-person audit.

## Corpus

137 labeled **entities** (ground truth in [`corpus.json`](corpus.json),
artifacts under [`artifacts/`](artifacts/)):

| Class | Count | Meaning |
|---|---|---|
| positive | 87 | a genuine AI agent or AI usage per the artifact's vendor semantics |
| control | 27 | clearly non-AI; any attributed in-scope finding is a false positive |
| near-miss | 23 | AI-adjacent vocabulary or shape without AI technology (crypto-exchange `api.gemini.com`, an MCP2515 CAN-bus library, a "Gemini Wallet" extension, `claudette-backup`); flagging it is a false positive |

The 87 positives carry 104 expected facts. Four positives are
**registered** in the supplied agent registry
([`artifacts/registry/agents.yaml`](artifacts/registry/agents.yaml)): a
Bedrock agent, a Copilot Studio bot, a GitHub App AI reviewer and Claude
Code on one laptop. Discovering them is still expected; classifying them as
shadow is not.

Each entity carries `<category>:<value>` facts from the tool-neutral
taxonomy in `tools/shadowbench/estate/taxonomy.py` (the code surface reuses
the code-surface benchmark's eight categories; the other surfaces add
`oauth-app`, `service-identity`, `token`, `bot-app`, `lowcode-agent`,
`cloud-ai`, `ai-client`, `model-store`, `gateway-caller`,
`ai-service-contact`, `agent-process`), evidence pointers, and **anchors**:
lowercase tokens grounded in the artifacts (app ids, ARNs, server names,
client IPs, or `host:user:tool` composites whose parts appear there). The
first anchor is the entity's primary anchor; primary anchors are unique
across the corpus, but an anchor can still occur in other files (see
[Bias and limits](#bias-and-limits)). Anchors are how the
scorer ties a tool's prediction to an entity; [Scoring](#scoring) gives the
rules. Tolerated facts (per entity, plus the corpus-level pairs under
`tolerated`) may be reported without penalty but are not required.

`corpus.json` `metadata.attribution` still describes attribution as
"longest anchor wins". The corpus is frozen, so that sentence was left as
written. It no longer matches the scorer; [Scoring](#scoring) does.

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

1. **Authoring.** The same maintainer wrote each surface's artifacts and
   labels together, from vendor semantics, in nine AI-assisted authoring
   passes, one per surface. `corpus.json` metadata calls these passes "the
   nine surface authors"; they were not nine people. Artifacts were checked
   to parse cleanly in ShadowScan's offline loaders (completeness only:
   exit 0, no warnings); labels were never changed because a tool missed or
   flagged an entity.
2. **Additions.** Agent session transcripts were added to the
   dev-laptop-01 and dev-laptop-02 home trees (`.claude/projects`,
   `.claude/history.jsonl`, `.cursor` agent transcripts, `.codex/sessions`,
   `.codex/history.jsonl`) so installed agents carry the at-rest artifacts a
   real endpoint would have; `artifacts/registry/` and
   `artifacts/services/` were added.
3. **Label-completeness audit.** Every runnable tool ran once; every
   prediction attributed to no entity was audited. The original pull
   request reports three outcomes: adapter normalization fixes, one
   secondary anchor, and one corpus-level tolerated pair (a bare "VS Code
   is present" client row; the corpus models the AI extension inside the
   editor as the entity, not the editor). Only the tolerated pair is
   recorded in the repository, in `corpus.json` `metadata.errata`. No
   entity labels changed.
4. **Freeze.** [`FREEZE.json`](FREEZE.json) pins the SHA-256 of 139 files:
   `corpus.json` and the 138 files under `artifacts/`.
   `python -m tools.shadowbench.estate verify-freeze` checks drift. The
   published run was produced after the original freeze. Since then,
   integration renamed the manifest's keys when the files moved to
   `artifacts/` (digests unchanged), and the three errata below changed
   digests.

**Erratum (integration, 2026-10-12).** The repository's `.vscode/` ignore
rule kept one frozen file out of the original pull request's commits:
`artifacts/home/dev-laptop-02/marcus/.vscode/extensions/github.copilot-1.388.0/package.json`,
the only artifact of `endpoint.copilot-ext-dl02`. Its original bytes were
lost with the authoring session, so a minimal extension manifest replaces
it and `FREEZE.json` records the replacement's digest. The entity's
evidence is the extension's directory name, which is unchanged; a tool that
reads the manifest itself may behave differently on a re-run than in the
2026-10-11 run. `.gitignore` now re-includes `.vscode/` under `artifacts/`,
and `tests/unit/test_shadowbench_estate.py` fails if any frozen file is not
tracked.

**Erratum (integration, 2026-10-12).** The original pull request named the
fictional organization *Vantor*, which is also the name a real company
adopted in 2025, and gave it tenant hostnames on real SaaS domains. Every
occurrence, in file contents, directory names, the three JWT payloads that
carried it, `corpus.json` and the recorded predictions in `runs.json`, was
replaced with the same-length, case-preserving name *Adatum*. The scorer of
that time gave a prediction to the entity with the longest matching anchor,
and a same-length name keeps every anchor's length, so re-scoring the
renamed `runs.json` with that scorer gave exactly the renamed
`metrics.json` and `REPORT.md`. `FREEZE.json` and the four synthetic-JWT
allowlist digests were recomputed. The scorer changed afterwards: it now
uses anchor length only to break ties (see [Attribution](#attribution)),
and the committed results were re-scored with it (see [Results](#results)).

**Erratum (integration, 2026-10-12).** The `comment` in
[`artifacts/services/services.json`](artifacts/services/services.json)
named the live-sim host `tools/estate_benchmark/simhost.py`, a path that
never existed in this repository. It now names
[`tools/shadowbench/estate/simhost.py`](../../../tools/shadowbench/estate/simhost.py),
and `FREEZE.json` records the file's new digest. Neither simhost, the
AI-Infra-Guard adapter nor the scorer reads the comment.

## Execution and isolation

The runner, [`runner.py`](../../../tools/shadowbench/estate/runner.py),
reuses the code-surface benchmark's scrubbed environment. Each command gets
an environment rebuilt from scratch: a `PATH` of any `extra_path` entries
from `tools.json` followed by `/usr/bin:/bin`, a private `HOME` and
`TMPDIR` per unit, telemetry opt-outs, and `HTTP(S)_PROXY` pointing at a
dead proxy (`http://127.0.0.1:9`) unless `run --keep-network` is given.
Adapters that read a home tree point `HOME` at that tree in the unit's
private estate copy instead. Commands run with stdin at `/dev/null` in
their own process group, which is killed on timeout
(default 900 seconds per command; the 2026-10-11 run used 540 with four
workers). Each command starts in its unit's output directory, and `run`
makes `--out`, `--estate` and `--tools` absolute first. Captured stdout and
stderr are cut at 5,000,000 bytes; a report captured under its own file
name that hits the limit fails the command.

**Private estate copies and the freeze.** Before anything runs, `run`
compares the estate and `corpus.json` with the freeze manifest (`--freeze`,
default [`FREEZE.json`](FREEZE.json)). On any digest difference it prints
`DRIFT` lines and exits 1 without running a tool. A symlink or special file
in the estate, or a malformed manifest, stops it before any tool runs with
a `corpus error` message and exit 2. Each unit then runs against its
own copy of the estate in a fresh temporary directory, and that copy must
match the frozen digests before the unit's commands start (otherwise the
unit is an error and incomplete). A cache or configuration a tool writes
through `HOME` therefore lands in its own copy, not in the source estate
or another unit's copy. After the matrix, the source is checked again, so
a write that reaches it some other way is caught: any drift is recorded
in `runs.json`, printed as `DRIFT` lines, and `run` exits 1. Each
`runs.json` row lists in `estate_changes` the files the tool added, changed
or removed in its own copy (informational, at most 50 names).

**What `runs.json` records.** `harness_commit` is the commit the harness
ran from (null when it cannot be read), and `harness_dirty` says whether
tracked files under `tools/` differed from it; untracked files are not
checked. `freeze.sha256` is the digest of the freeze manifest file,
`freeze.files` the number of digests it holds and `freeze.drift_after` the
drift found after the run. The committed 2026-10-11 `runs.json` predates
all of these fields and has none of them.

**`--as-user ACCOUNT`.** Commands then run through `setpriv` as that
account with only the scrubbed environment. The account owns the unit's
output directory and estate copy while its commands run; the scratch
directories are mode 0711, so it can reach its own copy but cannot list the
others. The runner creates capture files and `result.json` afresh through a
directory descriptor, never by path, and measures and cuts each capture
through the descriptor the tool wrote to. Before anything reads what the
account wrote, the runner takes both trees back and removes every symlink,
hard link and special file in them without following it. The row's
`removed_outputs` lists the entries removed from the output directory; an
entry outside the tool's `home/` and `tmp/` scratch marks the unit
incomplete. Without `--as-user`, tools run as the account that started the
harness; the 2026-10-11 run did not use `--as-user`.

**This is not a sandbox.** There is no filesystem, network or process
isolation. A tool can read anything its account can read, and the dead
proxy only stops clients that honour the proxy variables. The version
probes (`--version`, `--help`, a `version` subcommand for vet and Numbat,
or package metadata read through the tool's own Python) run before the
matrix as the invoking account with its own environment, outside the
scrubbed one. Run third-party tools only on an externally isolated,
disposable machine with no credentials.

**The benchmark is designed never to execute corpus content.** Tools that
enumerate MCP servers by launching them run with that behavior disabled or
blocked as far as the wrappers can:

- Snyk Agent Scan runs in `inspect` mode with stdin at `/dev/null`, so the
  per-server consent prompt auto-denies and every server is still
  inventoried.
- The Cisco MCP Scanner and Snyk Agent Scan wrappers put refusing shims for
  common server launchers first on `PATH` (`common.LAUNCHERS` in
  [`adapters/common.py`](../../../tools/shadowbench/estate/adapters/common.py):
  `npx`, `npm`, `node`, `uvx`, `pipx`, `python3`, `docker`, `podman`,
  `java`, `go` and others). Each shim prints why it refused and exits 126.
  Only those names are refused: any other command name on `PATH` (`sh`,
  `bash`, `perl`, `curl`, ...), an absolute command path in a client
  configuration, or a configuration that sets its own `PATH` still runs.
  The committed home configurations name only `npx` and one absolute path
  under `/home/dana/tools/`, which the corpus does not ship.
- Cisco MCP Scanner enumerates a server's tools by connecting to it, and
  servers it cannot start are absent from its results. With the configured
  servers refused or missing, an empty inventory is the expected outcome of
  that design rather than a corpus defect.

The 2026-10-11 run predates the shims. It ran with `PATH=/usr/bin:/bin`
and the dead proxy; whether `npx` was installed in those directories on
that machine is not recorded.

**Live-sim.** [`simhost.py`](../../../tools/shadowbench/estate/simhost.py)
serves mock Ollama and vLLM HTTP endpoints on loopback for the two services
in [`artifacts/services/services.json`](artifacts/services/services.json)
(ports 11434 and 8000), runs AI-Infra-Guard against them, then shuts down.
Every port is bound before the scanner starts; a busy port stops simhost
with exit 2 and a message naming the port, so the unit fails and is marked
incomplete instead of probing a real server. `tools.json`
`ai_infra_guard.port_offset` (an integer, default 0) is passed to simhost
as `--port-offset` and added to every scan target's port. The live-sim
stages nothing for the other eight runtime entities, and the scorer counts
the run as reaching only the two that `services.json` mirrors (see
[Attribution](#attribution)).

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

The runnable tools' versions are the ones `runs.json` `tool_versions`
recorded by probing the installed binaries. The ShadowScan entry is its
package version string: `main` had moved past the `v0.1.2` tag by
2026-10-11 without changing it, and the run did not record which commit was
installed. `runs.json` records no version for a tool it skipped; the
power-pwn and Cartography versions are the ones the original pull request
listed.

Exclusion evidence, recorded during provisioning on the machine that
produced the 2026-10-11 run:

- **power-pwn 6.0.0**: every discovery path (`recon`, `dump`,
  `copilot-studio-hunter`, `llm-hound`) requires a live Microsoft 365 /
  Power Platform tenant with interactive MSAL authentication or live
  internet scanning; there is no offline-export ingestion mode.
- **Cartography 0.143.0**: the AI-relevant modules (anthropic, openai, aws
  bedrock/sagemaker, gcp vertex) sync live APIs with admin credentials
  into a running Neo4j server; without Neo4j it exits 1
  (`ServiceUnavailable`); there is no offline-export ingestion mode.
- **AgentSight eBPF capture** (its primary runtime mode) was blocked on
  that machine: fentry/fexit BPF program loads returned `EPERM` while
  kprobe and ringbuf programs loaded fine. Only its local-session mode
  runs here, so its runtime surface stays out of scope.

Adapters live in `tools/shadowbench/estate/adapters/`; the registry there is
separate from the code-surface benchmark's registry on purpose. On the code
surface, vet, Agentic Radar and AgentDiscover run through the argv, accepted
exit codes, environment and normalization of the corresponding
`tools/discovery_benchmark` adapters. A command that adapter runs inside
the repository (vet's) is started there through a fixed `/bin/sh`
trampoline that changes into the repository and execs the unchanged argv,
so the argv recorded in `runs.json` carries that prefix. In the 2026-10-11
run vet's code commands started in the run directory instead; their argv
named the repository with `-D` either way. Those normalizers read a
missing report as nothing found: vet's when `vet.json` is missing, empty,
`null` or `[]`, Agentic Radar's for each framework whose report is missing
or unparseable, and AgentDiscover's when `scan.sarif` is missing. A run
whose commands all exited with accepted codes therefore counts as complete
without a report, unless every command exited non-zero (see
[Run completeness](#run-completeness)). The estate scorer differs from the
code-surface scorer (see [Scoring](#scoring)), so the code numbers here are
not interchangeable with that benchmark's.

On the endpoint surface, the Cisco MCP Scanner and AgentSight wrapper
scripts run every step and exit with the status of the first step that
failed, and the Snyk Agent Scan script exits with the scanner's own
status. Numbat's script exits with the status of `numbat agents` when that
step leaves no report, and with 0 otherwise (the adapter reads its exit 1
on an empty inventory as a valid result); its `scan` step only adds
evidence paths to the prediction text, and its exit status is not checked.
The normalizers differ in how strictly they read a report:

- Cisco MCP Scanner and AgentSight: a missing, empty or unparseable
  report, or one without the records they expect, is an adapter error, not
  an empty inventory. Cisco needs a `scan_results` list in every output;
  AgentSight needs a session record that names its agent (`comm`) in any
  report that is not an empty list.
- Snyk Agent Scan, Numbat and vet on home trees: a missing, empty or
  unparseable report is an adapter error, and so is one whose top level is
  not an object (Snyk) or a list (Numbat, vet), or one that holds entries
  none of which is a client or agent record. A record is, for Snyk, an
  object with a `servers` list, or with a `client` name and no `servers`;
  for Numbat, an object with an `agent` name and a `present` or `detected`
  field; for vet, an object with an `App` or `Name`, or a non-empty
  `MCPServer` object. An error report such as `{"error": ...}` or
  `[{"error": ...}]` is therefore an error, not an empty inventory. An
  empty object (Snyk) or list (Numbat, vet) reads as nothing found, and so
  does vet's `null`, which the code-surface vet adapter records vet writing
  when it finds nothing. Entries that are not records are skipped when the
  report also holds a record, and a Snyk `client` that is not a string
  names no client.

These rules are stricter than the 2026-10-11 adapters were, but they would
not have changed that run's rows: every committed Snyk Agent Scan, Numbat
and vet home prediction names its client or server as text, so it was read
from such a record, and the one Numbat row without predictions
(`home:win-laptop-03`) recorded `raw_count` 0, an empty list.

## Scoring

The scorer is
[`tools/shadowbench/estate/score.py`](../../../tools/shadowbench/estate/score.py);
its module docstring is the reference for the rules below.

### Attribution

Each prediction goes to at most one entity:

1. A prediction matching a corpus-level tolerated (fact, anchor) pair is
   dropped.
2. **Candidates** are the entities on the prediction's surface (the surface
   the adapter gave it or, when that is missing or unknown, the surfaces
   its fact's category lives on) that its run reaches. A run over one
   repository (`code:<repo>`) or one home tree (`home:<device>`) reaches the
   entities labeled with that unit plus the estate-wide entities with an
   artifact inside that tree, such as an MCP server configured in several
   homes. ShadowScan's whole-estate run (`estate`) reaches every entity.
   AI-Infra-Guard's live-sim run (`sim`) reaches only the entities a
   service in `services.json` stands in for, those whose primary anchor is
   a service's `anchor`: `runtime.ollama-serve-marcus` and
   `runtime.vllm-build-runner`. Without a services file it reaches
   nothing, and so does a run over any other unit.
3. Among candidates whose anchor occurs in the prediction text
   (case-insensitive substring), when all of them are positives, one that
   expects the predicted fact (exactly, or by category for a `generic`
   value) wins, then one whose expected or tolerated facts share the fact's
   category. When a control or near-miss is among them, that preference is
   skipped, so the preference never hands a flag on a negative to a
   positive whose anchor merely co-occurs. What is still tied, or every
   candidate when a negative is among them, goes to the longest matching
   anchor, then the first entity id; those two tie-breaks can still give
   such a prediction to a positive. For example, an
   `ai-service-contact:gemini` prediction whose text is
   `10.31.4.50 192.168.7.30` names the crypto-exchange near-miss
   (`10.31.4.50`) and the Gemini positive (`192.168.7.30`), and goes to the
   positive because the positive's anchor is longer. Every prediction that
   matched several candidates is counted and recorded with its candidates
   and the rule that chose its owner (`metrics.json` keeps up to 50 per
   tool, `REPORT.md` shows up to 15); it counts as **ambiguous** when the
   anchor length or the entity id chose, which is always the case when a
   negative was among the candidates.
4. **Fallback.** When no candidate's anchor matches and the run covers one
   repository or home tree, the prediction goes to the one candidate
   labeled with that unit that expects the fact: inventory tools print
   client names, not the corpus's anchors. Estate-wide entities never take
   the fallback. With no such candidate, or several, the prediction is
   unattributed.
5. **Scan targets** replace steps 3 and 4 for a run that records them in
   `detail.scan_targets`, one per prediction. Only the AI-Infra-Guard
   adapter does: for each prediction it records the `services.json` `id`
   of the mock service on the port the scanner reported. The scorer gives
   such a prediction, without reading its text, to the one candidate whose
   primary anchor equals that service's `anchor`, and counts it under
   `harness_attributed` in `metrics.json`. That is the harness mapping a
   scanned loopback port to the estate host it stands in for, not the tool
   naming the host. A target that names no service, or matches no single
   candidate, leaves the prediction unattributed and is counted under
   `unknown_scan_target`. A malformed record marks the run incomplete and
   leaves all its predictions unattributed. A target that is not one line
   of at most 160 letters, digits and `._:/-`, starting with a letter or
   digit, makes the record malformed, so its text reaches neither
   `metrics.json` nor `REPORT.md`.

An attributed prediction takes its entity's surface, so it is in scope
exactly when the tool declares that surface. Unattributed predictions are
false positives; one is in scope when its own placement touches a declared
surface or cannot be placed at all. Predictions outside the declared
surfaces count in the estate-wide numbers only.

### Run completeness

A run (one tool on one unit) is **incomplete** when its status is not
`ok`, the adapter flagged it incomplete (ShadowScan's adapter accepts its
exit 3 but flags the run when the report says the scan was incomplete), it
recorded an error, its scan-target record is malformed, it ran no command,
a command timed out or exited with a code the adapter does not declare as
success, or every one of its commands exited non-zero and it produced no
output. The last rule exists because Agentic Radar accepts exit 1 from
each of its five scans, through the code-surface adapter it wraps, and
without stderr "nothing found" cannot be told from a crash. AgentDiscover
accepts exit 1 only from its `export-mcpfw-policy` step; its `scan` and
`deps` steps must exit 0, so a run of it in which every command exited
non-zero is already incomplete by the exit-code rule.

A code or home unit that labels an entity on a tool's declared surfaces is
**missing** when the tool has no run for it and no whole-estate (`estate`)
run; a `sim` run does not count as one. A tool with no runs at all is
missing everywhere.

Every entity an incomplete or missing run reaches is **unscored** for that
tool: its expected facts count as missed, a positive is not detected, and a
negative earns no true negative (a flag on it is still a false positive).
An in-scope entity that no complete run reaches is **not reached**, with
the same consequences. The four endpoint entities whose only artifacts are
offline exports under `artifacts/endpoint-exports/` (three positives, one
control) are outside every home tree, so the per-home tools never reach
them. Likewise the live-sim never reaches the eight runtime entities no
mock service stands in for (four positives, two controls, two near-misses).
Other non-zero exits an adapter declares as success are counted in
`REPORT.md` under Run status but not treated as failures.

### Metrics

- **Entity level, in scope.** Only entities on the tool's declared
  surfaces. A positive is detected when an attributed prediction matches
  one of its expected facts; a control or near-miss is flagged by any
  attributed prediction. An unflagged negative is a true negative only
  when a complete run reached it and no incomplete or missing run did.
  This yields TP / FP / TN / FN, precision, recall and F1 over entities.
- **Value level.** Exact facts, micro-averaged, with per-surface
  breakdowns. `<category>:generic` consumes one expected fact of its
  category; a surplus generic on a category already matched is neither
  credited nor charged (the code-surface scorer credits it). Tolerated
  facts are dropped first, and unattributed in-scope predictions are false
  positives. *In-scope* counts only a tool's declared surfaces.
- **Estate-wide.** Positives detected out of all 87, and value recall
  over all 104 expected facts on the nine surfaces: the cost of partial
  surface coverage.
- **Shadow layer.** For tools that emit a registry verdict: detected
  registered entities should read registered, detected unregistered
  positives should read shadow.
- Adapters drop facts outside the taxonomy, so they are never penalized.
  Timings are indicative only (units run in parallel).

The code-surface scorer scores an incomplete run on the facts it found;
this scorer gives an incomplete run nothing. That and the surplus-generic
rule are why the code numbers here differ in kind from that benchmark's.

## Results

Committed under [`results/2026-10-11/`](results/2026-10-11/):

- `runs.json`: per-unit statuses, argv, exit codes, timings, raw record
  counts, adapter detail and the normalized predictions;
- `metrics.json` and the rendered
  [`REPORT.md`](results/2026-10-11/REPORT.md);
- `tools.json`: the shape of the tool configuration.

Local paths in `runs.json` and `tools.json` were replaced by placeholders
(`<tools>`, `<run>`, `<estate>`, `<repo>`, `<venvs>`) before publishing.
The harness writes real paths, and no script in the repository does the
replacement. No stdout, stderr or raw tool report was committed.

`metrics.json` and `REPORT.md` are a re-score of the 2026-10-11 `runs.json`
with the scorer as fixed during integration on 2026-10-12, so they differ
from the numbers the original pull request published. Running `score` and
`report` on the committed `runs.json` at this commit reproduces both files
byte for byte.

Headline, in the order `REPORT.md` lists the tools (by in-scope value F1).
Letters in brackets point to the [disclosures](#disclosures-for-the-2026-10-11-run)
below.

| Tool | Declared surfaces | Units run (status) | In-scope positives detected | In-scope negatives: flagged / true negatives / total | In-scope value P / R / F1 | Estate-wide positives detected | Estate-wide value recall |
|---|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) 0.1.2 | all nine | 1 (ok) | 83/87 | 8 / 42 / 50 | 92% / 95% / 93% | 83/87 | 95% |
| Snyk Agent Scan (mcp-scan) 0.6.8 | endpoint | 3 (ok) | 9/19 | 0 / 5 / 6 | 100% / 47% / 64% | 9/87 | 9% |
| AgentDiscover 2.9.5 | code | 10 (ok) | 5/6 | 0 / 4 / 4 | 100% / 35% / 52% | 5/87 | 8% |
| AI-Infra-Guard 4.6.5 | runtime | 1 (ok) [a] | 2/6 [a] | 0 / 4 / 4 [a] | 100% / 33% / 50% | 2/87 | 2% |
| SafeDep vet (ai discover) 1.20.0 | code, endpoint | 13 (ok) | 11/25 | 0 / 9 / 10 | 100% / 29% / 44% | 11/87 | 12% |
| Numbat 0.2.0 | endpoint | 3 (ok) | 4/19 | 0 / 5 / 6 | 100% / 21% / 35% | 4/87 | 4% |
| Agentic Radar 0.14.1 | code | 10 (ok), 8 incomplete [c] | 2/6 | 0 / 0 / 4 | 100% / 9% / 16% | 2/87 | 2% |
| AgentSight (local sessions) 1.0.34 | endpoint | 3 (ok) [b] | 1/19 | 0 / 5 / 6 | 100% / 5% / 10% | 1/87 | 1% |
| Cisco MCP Scanner 4.8.6 | endpoint | 3 (ok) [b] | 0/19 | 0 / 5 / 6 | n/a / 0% / n/a | 0/87 | 0% |

Every unit of every tool recorded status `ok`. Under the completeness rule
only Agentic Radar has incomplete units: on 8 of its 10 repositories all
five scans exited 1 and reported nothing. The per-home tools (Snyk Agent
Scan, Numbat, AgentSight, Cisco, and vet on the endpoint surface) did not
reach the four endpoint-export entities, so each could detect at most 16 of
the 19 endpoint positives and earn at most five true negatives of six.
An in-scope value precision of 100% means no in-scope false positive,
attributed or not, among few predictions; it is not a precision estimate.
No prediction in the run was unattributed or ambiguous: all 41 predictions
that matched several entities, all of them client-versus-MCP-server pairs
in one configuration file, were settled by the expects-the-fact rule.

ShadowScan's four misses are four of the hard positives listed under
[Corpus](#corpus) (the text-generation-inference caller, the n8n
`httpRequest` flow, the k8s vLLM workload and the Wudpecker notetaker). It
flagged eight negatives (two controls, six near-misses), listed in the
report's control and near-miss grid. Its registry layer gave all 83
detected positives the expected verdict (79 shadow, 4 registered). No other
tool flagged a control or near-miss in this run. That is partly precision
and partly coverage: 36 of the 50 negatives sit on surfaces only ShadowScan
declares. On the endpoint surface, Snyk Agent Scan and vet reached the same
value F1 (64%, 9 of 19 expected facts); on the code surface AgentDiscover
detected five of the six code positives, at 35% value recall.

### Disclosures for the 2026-10-11 run

- **[a] AI-Infra-Guard's two detections came from the harness.** The
  adapter of that time appended each mock service's `services.json`
  anchor, the answer key, to the prediction text
  (`dev-laptop-02:marcus:ollama`, `build-runner-3:ci:vllm`); the part of
  the scanner's output the adapter kept was the loopback URL and its
  fingerprints. The committed `runs.json` keeps that text and records no
  scan targets, so the scorer still attributes both predictions through
  the appended anchors. Scored at this commit with the appended anchor
  removed and no scan target, the two predictions are unattributed false
  positives: 0/6 detected, in-scope value 0 TP / 2 FP / 6 FN, 0/87
  estate-wide. The current adapter no longer appends the anchor; it
  records each prediction's scan target, and the scorer attributes it
  through `services.json` as described under
  [Attribution](#attribution). With those targets the same two predictions
  score 2/6, as harness attribution of a scanned loopback port to the host
  it stands in for, not as the tool naming the host. The live-sim stands in
  for two of the six runtime positives. Its four true negatives are the
  runtime controls and near-misses, which the live-sim does not stage: a
  `sim` run counts as reaching every entity, so the scorer credits them.
- **[b] Cisco MCP Scanner and AgentSight "ok" came from wrappers that
  always exited 0.** Their wrapper scripts at the time ended with `exit 0`
  whatever the scanner did. AgentSight's normalizer read a missing or
  unparseable report as an empty one; Cisco's skipped unparseable outputs
  and read an object without `scan_results` as zero servers. Their
  statuses, and the five true negatives each now receives, therefore do not
  show that the scanners ran cleanly. Cisco produced no record on any of
  its three home trees; AgentSight produced one record on dev-laptop-01 and
  none on the other two. The current wrappers exit with the first failing
  step's status, and the current normalizers treat a missing, empty or
  unparseable report, or one without the records they expect, as an error
  (see [Tools](#tools)).
- **[c] Agentic Radar's exit 1.** 48 of its 50 commands exited 1, which its
  adapter (shared with `tools/discovery_benchmark`) accepts as success. On
  8 of 10 repositories every scan exited 1 and nothing was reported; the
  scorer treats those units as incomplete, so their four positives count as
  missed and their four negatives earn no true negative. The other two
  units each had one scan exit 0 with output and count as complete, even
  though an exit 1 among their other scans could have been a crash.
- **[d] No stderr was committed.** `runs.json` holds argv, exit codes,
  timings, statuses and normalized predictions, not the tools' stdout,
  stderr or reports, so what an accepted non-zero exit meant cannot be
  checked from the published results.
- **[e] Provenance.** The run recorded no harness commit and no freeze
  digest (those fields came later), and ShadowScan's version is recorded
  only as `0.1.2` (see [Tools](#tools)). The run used neither the launcher
  shims nor the current wrappers, and vet's code commands started in the
  run directory.

## Reproduce

From the repository root:

```
python -m tools.shadowbench.estate validate
python -m tools.shadowbench.estate verify-freeze
python -m tools.shadowbench.estate run \
    --tools /srv/estate/tools.json --out /srv/estate/runs --workers 4
python -m tools.shadowbench.estate score \
    --runs /srv/estate/runs/runs.json --out metrics.json
python -m tools.shadowbench.estate report --metrics metrics.json --out REPORT.md
```

`validate` checks the corpus, that every artifact and unit directory
exists, that each primary anchor is grounded in its entity's artifacts and
that the estate holds no symlink or special file. It prints a `WARN` line
for each anchor that also occurs in a file outside its entity's artifacts;
`--strict` turns those warnings into a failure. On the committed corpus it
reports 12 such warnings and exits 0.

`run` takes `--freeze` (default `FREEZE.json`), `--timeout` (seconds per
command, default 900), `--as-user ACCOUNT`, `--keep-network` and
`--only TOOL[,TOOL...]`. `score` reads `services/services.json` under
`--estate` (default `benchmarks/shadowbench/estate/artifacts`) to resolve
scan targets and the live-sim run's reach. A malformed services file stops
it with a `corpus error` and exit 2. When the file is missing or lists no
service and some run needs it (a `sim` run, or one that records scan
targets), `score` names those runs and exits 2 without writing anything.
With `--allow-missing-services` it prints a note instead and scores them
anyway: every scan target is then unattributed and a `sim` run reaches no
entity. To re-score the committed run, pass
`--runs benchmarks/shadowbench/estate/results/2026-10-11/runs.json`.

`tools.json` maps tool ids to installed binaries:
`{"extra_path": "...", "tools": {"<id>": {"bin": "..."}}}`.
AI-Infra-Guard also needs its `fps` and `vul` data directories and takes an
optional integer `port_offset`. `results/2026-10-11/tools.json` shows the
shape with placeholder paths; it records no versions. Install the versions
in `runs.json` `tool_versions` (the [Tools](#tools) table) for a faithful
reproduction.

## Bias and limits

- **No independent review.** One maintainer wrote the scanner, the
  harness, the artifacts and the labels, using AI assistance. Files under
  [`archive/reviews/`](../../../archive/reviews/) and green CI are not a
  second person.
- **Format selection favors ShadowScan.** The artifact formats are the
  offline export formats ShadowScan parses; tools whose native modality is
  a live API (power-pwn, Cartography) or a kernel (AgentSight's eBPF)
  cannot show their strength against an offline corpus. The per-surface
  tables and the exclusion notes above are the honest reading, not the
  single headline number.
- **Trigger knowledge.** The author knew the documented detection triggers
  of ShadowScan and, to a lesser extent, of the other tools. Mitigations:
  hard positives beyond documented triggers, negatives ShadowScan itself
  over-flags (verified: it flags eight), per-entity rationale, and every
  run's normalized predictions committed. The tools' raw output was not
  committed.
- **Anchor collisions.** `validate` reports 12 anchors that also occur
  outside their entity's artifacts. Some are deliberate (the agent registry
  names three registered entities, the live-sim services file names the two
  runtime entities it mirrors); others are not, for example
  `.cursor/mcp.json` in a code repository, `server-github` in the runtime
  process export and `api.gemini.com` in cloud, gateway and low-code
  artifacts. Attribution considers only entities on the prediction's
  surface, which keeps most of these apart, but a prediction placed on the
  colliding entity's surface can still be attributed through one. Fixing
  them needs a new freeze.
- **Reach comes from the unit, not from what a tool read.** The scorer
  decides which entities a run could see from its unit alone: a repository
  or home tree, the whole estate, or the entities the live-sim's
  `services.json` mirrors. ShadowScan's `estate` run reaches every entity,
  so an unflagged negative on its surfaces is a true negative whether or
  not one of its connectors parsed that negative's artifact.
- **One estate, one snapshot.** 137 entities authored by one process on
  one date; the corpus cannot measure field base rates, scale behavior, or
  live-collection reliability.
- **Author-written corpora cannot establish production precision.** See
  [`docs/evaluation.md`](../../../docs/evaluation.md) for what ShadowScan
  accepts as evidence.
