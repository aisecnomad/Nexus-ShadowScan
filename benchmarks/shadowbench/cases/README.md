# ShadowBench: the nine-surface shadow AI agent discovery benchmark

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
tool. It reports precision, recall, F1, specificity, balanced accuracy, MCC,
agent-tier recall and false-alarm rate and estate-wide recall, with confidence
intervals, and exact McNemar tests between paired tools.

The harness is `tools/shadowbench/cases/` ([its README](../../../tools/shadowbench/cases/README.md)
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
> committed and hashed. The committed corpus's own seed had no effect on its
> cases (see Random streams); a corpus generated now at another seed differs.

## What is measured

A case is one input a tool is pointed at: an identity-provider export, a
gateway log window, a low-code platform export, a SaaS admin export, a cloud
account's CLI outputs or a Kubernetes workload list, a developer's home
directory, a workstation's network window or a set of listening services, a
host's process table, or a repository checkout. Each case lists:

* **expected entities**, each with a key, a label (`agent` or `llm`) and the
  evidence that justifies it;
* **tolerated keys**: supporting records a tool may report without penalty
  or credit (a client's parent directory, an agent's execution role, a pending
  install request);
* **decoys**: records labeled `none` whose keys form the true-negative
  universe (service accounts without AI, monitoring *agents*, Minecraft
  *Bedrock* servers, apps named *copilot*, classic chatbots, plain workloads).

Labels: `agent` is an autonomous or tool-using AI agent or an agent
integration (a configured MCP server, Copilot Studio agent, Bedrock agent,
coding-agent CLI, agent framework process); `llm` is AI use without agent
evidence (a chat SaaS app, a model server, a single-completion caller, a GPT
step in a flow); `none` is no AI. Exact rubrics per surface are the module
docstrings under `tools/shadowbench/cases/families/`.

Entity keys are tool-neutral identifiers from the platform's own data: the
Okta app id or Entra `appId`, the gateway key alias or principal ARN, the
Power Platform bot or flow id, the n8n workflow id, the Slack app id or GitHub
App slug, the AWS ARN or `namespace/Kind/name`, the artifact path under the
home directory, the client address or `ip:port`, the pid, and for code the
`<category>:<value>` facts of the [code-surface benchmark](../../shadow-ai-discovery/README.md).

### Surfaces, modalities and inputs

| Surface | Modality | What the tool is pointed at | Cases | Expected entities | Decoys |
|---|---|---|---|---|---|
| code | checkout | 26 public repositories pinned by commit (16 positive, 4 control, 6 near-miss) | 26 | 109 facts | 0 (controls and near-misses: any reported taxonomy fact that is not tolerated is a false positive) |
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
| endpoint | home | a developer home directory, given to the tool as `HOME` | 40 | 24 | 0 (negative homes: any reported key that is not tolerated is a false positive) |
| network | passive | Zeek `conn`, `ssl`, `dns`, `http` logs of one workstation's window | 20 | | |
| network | active | loopback services served inside the tool's network namespace | 20 | 44 | 50 |
| runtime | snapshot | osquery process rows and osqueryd result-log lines | 20 | | |
| runtime | live | inert processes spawned under the recorded names and command lines | 20 | 98 | 165 |

346 cases, 738 expected entities, 735 decoys. Within a surface the second row
of each pair carries the surface's totals.

Two modalities make tools that only work live measurable offline. **Active
network** cases start mock services inside the tool's network namespace
(`tools/shadowbench/cases/mockserv.py`), always bound to `127.0.0.1`, each
answering the routes a fingerprinting scanner probes the way the real product
does: Ollama's `/api/tags`, vLLM's `/v1/models`, Open WebUI's `/api/config`, an
MCP server's `initialize`, an OpenClaw gateway's `/health`, and decoys such as
a Grafana login page, a Jenkins banner, a Datadog Agent Manager page and a
Minecraft *Bedrock* panel. **Live runtime** cases spawn an inert static binary
under each recorded process name with the recorded command line, inside the
tool's PID namespace, so a tool that reads `/proc` sees exactly the processes
a snapshot describes. The current harness runs them as the tool's own
unprivileged user; in the 2026-10-11 run they and the tools ran as root.
Reported pids are translated back to the corpus's process keys.

### Platform-native inputs and conversions

Inputs are the platforms' own shapes, so no tool is handed another tool's
format. Where a tool reads its own offline format, its adapter converts and the
conversion is documented in the adapter docstring. ShadowScan's adapter embeds
Okta grants and tokens into the app list, concatenates the Graph arrays with a
role-id map, concatenates the Power Platform and Slack collections, and re-keys
the AWS CLI outputs into its dumped record kinds; IAM roles are not converted
(its offline IAM record needs pre-analysed policy fields), so ShadowScan never
sees an IAM-role decoy. Its adapter declares those decoys as withheld, and the
scorer leaves them out of ShadowScan's specificity (see Metrics). Everything
else is read unchanged.

## Metrics

Per tool, per surface and per modality, over the cases the tool ran
(`tools/shadowbench/cases/score.py`; its module docstring is the exact rule):

* **Matching.** A reported key equal to a tolerated key is neither credited
  nor penalized. Otherwise it matches an expected or decoy key when the two
  are equal or, for `artifact:` keys (home-directory paths), when the
  reported path lies inside the expected or decoy directory (a tool that
  cites a file in Claude Code's `.claude` directory has found it). Matching
  is one-way: a reported ancestor directory of an expected file never
  matches. The directories a tool may name instead are tolerated keys, which
  earn no credit. Reported keys are de-duplicated.
* **Entity level.** A matched expected key is a true positive and an unmatched
  one a false negative. A reported key that matches nothing expected or
  tolerated is a false positive; one that hits a decoy also counts against
  specificity. A decoy left alone is a true negative only on a complete `ok`
  run. Precision, recall and specificity carry Wilson 95% intervals; F1 a
  2,000-sample case bootstrap interval.
* **Code surface.** Truth there is `<category>:<value>` facts from
  `tools.discovery_benchmark.taxonomy`. A reported code key that is not such a
  fact (for example a file path an adapter could not map) is out of taxonomy:
  neither a true nor a false positive. The rule is the same for every tool,
  and the count is reported per tool.
* **Agent tier.** Recall on expected `agent` entities counting only reports
  labeled `agent`; the false-alarm rate on expected `llm` entities and decoys
  that a tool labeled `agent`. A tool that cannot tell agents from plain AI
  use reports `ai` and earns no agent-tier credit. An error row is left out of
  the false-alarm universe, and an incomplete run adds only the entities it
  did call agents.
* **Case level.** A positive case is found only when the tool reports at least
  one expected entity (a true positive); a false positive alone does not find
  it. A negative case is a false alarm when the tool reports any false
  positive, and is correct only on a complete `ok` run. Case recall,
  specificity, balanced accuracy, MCC and the McNemar test use these outcomes.
* **Errors, missing rows and incomplete runs.** A crash, timeout or unreadable
  output is an `error` row, and a case with no row counts as an error and is
  also reported as missing. An error is never a correct outcome: every expected
  entity is missed, the decoys stay in the specificity denominator without
  being true negatives, a positive case is missed and a negative case is a
  false alarm. A run marked incomplete (the tool says so, as with ShadowScan's
  exit 3, or the runner flags an exit outside the adapter's accepted codes that
  still reported entities) keeps the true and false positives it reported but
  never earns a true negative: its unflagged decoys are not true negatives,
  and a negative case it scanned incompletely is a false alarm. A positive
  case it found still counts as found. Incomplete runs are also counted
  separately.
* **Withheld decoys.** An adapter that converts a case's input may declare
  the decoys whose records its conversion never passes to the tool, by key
  prefix per surface and modality (`withheld_decoys`); ShadowScan's adapter
  declares the AWS IAM roles it does not convert. A withheld decoy is left
  out of that tool's specificity and agent false-alarm denominators, so a
  record the tool never saw earns it no true negative, unless the tool
  reports it anyway, which counts against it like any decoy hit. A negative
  case whose every decoy was withheld, scanned completely with no false
  positive, is left out of that tool's case-level results and the paired
  comparison; an error, an incomplete scan or a false positive there is
  still a false alarm. The metrics count both (`decoys_withheld`,
  `case.negatives_withheld`), and the report names them.
* **Estate recall.** True positives over all 738 expected entities in the
  corpus, charging a tool for every surface and modality it does not run
  (those rows are `unsupported` and left out of in-scope metrics).
  **Coverage** is the number of surfaces on which the tool ran at least one
  case, so a tool that runs one modality of a surface covers it.
* **Paired comparison.** Exact McNemar test on case-level correctness against
  the reference tool (ShadowScan unless `score --reference` names another) over
  the cases both ran.
* **Timing.** Median, p90 and maximum seconds per `ok` case (indicative only;
  runs are parallel).

The scorer also checks what it is given. The run manifest must name the
SHA-256 of the corpus file being scored, because case ids are positional;
every `<tool>.jsonl` must belong to a tool the manifest records as run; and
the row statuses in each file must add up to the counts the manifest recorded.
Each of these is refused unless `score --force` is given, and a forced score
lists every override in `metrics.json` and at the top of the report. Malformed
rows are refused even with `--force`: an unknown status, a second row for a
case, a case the corpus does not have, a row whose tool, surface, modality,
family, label or difficulty disagrees with its file or case, and an
`unsupported` row beside `ok` or `error` rows on the same surface and modality.

## How the corpus is built, and how to check it

`python -m tools.shadowbench.cases generate --seed <seed> --per-surface 40 --output corpus.json`
writes a corpus; the committed one is rebuilt as described under Random
streams below. Each export-style case draws entity families by quota (45%
agent, 15% plain AI, 40% decoy, with at least one decoy slot per export except
on the gateway surface, which has no decoys), redraws collisions, and renders
the platform's files. Endpoint and passive-network cases reuse the 25 endpoint
and 17 network families the earlier head-to-head benchmark pre-registered in
`tools/benchmark/`, adding the artifact or client key each family plants.
Code cases come from the pinned
[code-surface corpus](../../shadow-ai-discovery/corpus.json), whose facts and
tolerated facts are carried over; `provider:*` facts are `llm`, all others
`agent`. Without that file the generator refuses to run rather than write a
corpus with no code surface.

The corpus header records the seed and a SHA-256 over the generator sources,
each named by its repository-relative path: the generator and its case model
(`generate.py`, `corpus.py`, `contract.py`), its families, the
`tools/benchmark` families it reuses and, in the current code, the
code-surface corpus. Corpora written now also record the `--per-surface`
count and the stream scheme (below). The committed corpus predates both
fields; `verify` infers 40 from its largest generated surface and uses the
legacy stream scheme. Its recorded digest was computed before the
harness moved to `tools/shadowbench/cases/` and before the digest covered the
code corpus, so it no longer matches the current sources.

`python -m tools.shadowbench.cases verify --corpus corpus.json` loads and
validates the corpus, prints its stream scheme and the recorded and the
current generator digest, then rebuilds the cases from the current sources at
the recorded seed, per-surface count and stream scheme and compares the
parsed case lists; the header, the `created` stamp and the formatting are not
compared. It always rebuilds, because a matching digest says only that the
sources are unchanged, not that nobody edited the cases. Identical cases exit
0 even when the digests differ, and verify says that the sources changed but
build the same cases; any difference exits 1 and names the first differing
case (or, when one list is a prefix of the other, the two case counts).
`--regenerate` is still accepted and changes nothing. The committed corpus
passes, with that note about its digest. Anyone can use it to confirm that
the committed cases are what the current generator builds. To test for
overfitting to this corpus, generate a fresh one at another seed with the
default `sha256` scheme (the generator prints the scheme, and `verify` names
it); a corpus generated before this fix used the legacy streams whatever its
seed. The run manifest names the corpus hash, the generator digest, the
platform and each tool's version or commit; manifests written by the current
runner also name the harness commit.

### Random streams

Each generated surface and modality draws its cases from its own random
stream. Corpora written now record `"stream_scheme": "sha256"`: each stream
is seeded from a SHA-256 of the seed, the surface and the modality, so every
seed builds its own cases and no two modalities share a stream.

**The committed 2026-10-11 corpus was built with an older, faulty
derivation**, which its header does not name and which the generator keeps
as the `legacy` scheme only so that the corpus still rebuilds. It turned the
text `<seed>:<surface>:<modality>` into an integer and kept the last 62 bits,
which always fall inside the modality name. As a result:

* **The seed had no effect.** Under that derivation every seed builds the
  committed 346 cases at `--per-surface 40`, so before this fix a rerun
  "with your own seed" rebuilt this corpus, and no comparison across seeds
  was possible. Whatever seed the 4-case-per-surface smoke corpus the
  adapters were calibrated on (see Bias controls) was generated at, it drew
  from the scored corpus's own streams; its cases differ from the scored
  ones, but it was not an independent draw.
* **Four pairs of modalities shared one stream**: Okta and Entra,
  LiteLLM and Power Platform, Bedrock logs and Slack, AWS and Kubernetes.
  Within each pair the case labels come in the same order, case for case (on
  the gateway side, which has no decoys, a planned `none` case becomes
  `llm`). The number of cases with each label is fixed by quota whatever the
  stream, and the entities inside the cases differ, because each platform's
  families consume the stream differently; only the first draws coincide
  (the first Okta and Entra cases have the same entity count). So the two
  modalities of a pair are not independent draws, and nothing in the
  committed results shows how the numbers vary from one seed to another.

`verify` prints the scheme a corpus uses and the modalities that share a
stream under it. `generate --seed 20261011 --per-surface 40
--stream-scheme legacy` rebuilds the committed cases (with the scheme
recorded in the header); never use `legacy` for a new corpus.

### Bias controls

* By the author's account, the rubrics, families, generator, adapters and
  original scorer were written before the scored run, and the adapters were
  calibrated on probe inputs and a 4-case-per-surface smoke corpus, never on
  the scored corpus. That smoke corpus drew from the scored corpus's own
  random streams, because the seed had no effect (see Random streams). The
  git history cannot confirm any of this: the harness, the
  rubrics, the corpus and results were first committed together, in one
  commit. Calibration changes are recorded in each adapter's docstring.
* The published metrics do not come from that original scorer. Its rules were
  revised after the run, during integration review and with the run's results
  in view: one-way artifact matching, a true positive needed to find a case,
  no true negative from an error, a missing row or an incomplete run, and
  out-of-taxonomy code keys counted apart. The revised rules were re-applied
  to the unchanged rows (see Integration changes under Results). The adapters
  were also changed after the run; the committed rows come from the earlier
  adapters.
* Decoys are drawn from the confusions real tools make: service identities
  without AI, infrastructure *agents*, *Bedrock* game servers, *MCP* (Minecraft
  Coder Pack, Microsoft Cloud Partner), *copilot* seat reports, *Gemini*
  exchange clients, embedding batches that look like agent loops, classic
  chatbots, flows and workflows whose names mention AI.
* Every tool runs as uid and gid 65534 with `no_new_privs`, in fresh network,
  PID and mount namespaces: no network beyond loopback (where active-network
  cases serve their mocks), no view of host processes (live-runtime cases show
  only the case's inert processes), `/root` and `/home` hidden under empty
  tmpfs mounts, and an environment built from scratch with a case-local `HOME`
  and no inherited credentials. This is not a sandbox: a tool can still read
  world-readable files elsewhere on the host. The
  [harness README](../../../tools/shadowbench/cases/README.md) gives the
  details. This is the current harness: the 2026-10-11 rows were recorded
  under weaker isolation, described under Integration changes. No tool is
  given an allowlist, an inventory or a known-agent list.
* Tools are scored only on surfaces and modalities they declare; estate recall
  shows the cost of the surfaces they do not cover without penalizing their
  in-scope precision.
* The runner keeps each tool's raw output (exit codes, the tail of stdout and
  stderr, and the adapter's parse) under `raw/` in its own output directory,
  beside the normalized rows, so the mapping can be audited and re-applied on
  that machine. Raw output is not committed; the committed results hold the
  normalized rows only.
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
  exactly as it would on the real product. The mocks' answer to unknown paths
  was not fixed blind. The decoy mocks answer with HTML pages, as the real
  products do. An earlier version of this README reported AI-Infra-Guard's
  clean decoy result as holding "after they answered unknown paths with HTML",
  which indicates that this behaviour was settled with that tool's response to
  JSON error bodies in view.
* **The gateway surface has no decoys.** Every caller in an LLM gateway log
  uses a model, so the gateway test is agent tier only.
* **Small per-surface samples.** Twenty cases per modality on most surfaces
  (40 endpoint homes in its one modality, 26 code repositories) give wide
  intervals; the report prints them. Regenerate at a larger `--per-surface`
  for narrower ones.

## Tools

| Tool | Version benchmarked | Surfaces it ran on | How it is run |
|---|---|---|---|
| ShadowScan (Project Nexus) | the checkout named in `tools.json` (0.1.2 at `2d43f508fc95` in the 2026-10-11 run) | all nine; network passive only | one offline connector per modality (see the adapter docstring); `endpoint.inventory` on the home, `runtime.processes` on `/proc` for live cases |
| Snyk Agent Scan | 0.6.8 | endpoint | `snyk-agent-scan inspect --json` with `HOME` set to the case, consent prompts declined (no server started, nothing uploaded) |
| Cisco MCP Scanner | 4.8.6 | endpoint | `mcp-scanner known-configs --analyzers yara`; every server its debug log names from a config under the home counts, whether or not it could start offline |
| Microsoft Agent Governance Toolkit, `agent-discovery` | 5.0.0 | code, endpoint, runtime (live) | `scan -s config` on the repository or home; `scan -s process` in the PID namespace; its own process is ignored |
| AgentDiscover Scanner | 2.9.5 | code, endpoint | `scan-all --skip-layers 2,3,4,5 --format json` |
| Numbat (Perplexity) | 77ece3a (2026-10-09) | endpoint | `numbat agents --format json` with `HOME` set to the case; its unit is the client's configuration directory |
| SafeDep vet | v1.20.0 | code, endpoint | `vet ai discover --scope project` / `--scope system` |
| AI-Infra-Guard (Tencent) | v4.6.5 (d9f3aa4) | network (active) | `ai-infra-guard scan -t ip:port ...` with its fingerprint files offline |
| Fleet `ai_tools` table | fleetdm/fleet cf1217b (2026-10-11) | endpoint, runtime (live) | the table's `Generate` function compiled into a small Go program (`fleet-ai-tools`), no osquery daemon needed; rows outside the case home are dropped |
| Cartography, Copilot Studio Kit, k8s-aibom, AgentSight | — | not run | no offline entry point; see Known limits |

Each adapter's docstring records the version, the exact command and the
output-to-entity mapping. `install_tools.sh` in the harness directory
reproduces the installations at the pinned versions and commits and writes
those versions into the `tools.json` it creates. The runner copies a
`version` found there into the manifest unchecked, for every tool, and probes
only tools without one. Installs are version-pinned, not hash-locked:
transitive dependencies resolve at install time, so a later install can
differ below the pinned tools.

## Results

Committed runs live under `results/<date>/` with `manifest.json` (corpus path
and hash, generator digest, platform, and per tool its version and row-status
counts; from the current runner on, also the harness commit and whether
anything under `tools/` differed from it, which the report then names), one
`<tool>.jsonl` of normalized rows, `metrics.json` and `REPORT.md`. The
runner's raw output stays on the machine that ran it and is not committed.
The newest `REPORT.md` holds the measured numbers; read them with the caveats
above. Scoring needs no third-party tool, so anyone can check the committed
metrics from the committed rows:

```bash
python -m tools.shadowbench.cases score --corpus benchmarks/shadowbench/cases/corpus.json \
    --results benchmarks/shadowbench/cases/results/2026-10-11 --out /tmp/metrics.json
```

### Integration changes

This track was pull request #193. When it was integrated beside the estate
track:

* The corpus, the results and the harness moved into the `cases/`
  subdirectories of `benchmarks/shadowbench/` and `tools/shadowbench/`. The
  corpus file, `manifest.json` and every `<tool>.jsonl` of the 2026-10-11 run
  kept their exact content; the manifest still names the corpus at its old
  path, `benchmarks/shadowbench/corpus.json`.
* The vendor letter grades (`grades.json`), the PDF report and the code that
  produced them were removed.
* The generator's `--seed` had no effect, and four pairs of modalities
  shared a random stream (see Random streams). New corpora seed each stream
  from a SHA-256 of the seed, surface and modality and record
  `"stream_scheme": "sha256"`; a corpus without the field, the committed one
  among them, is rebuilt with the legacy derivation, so its cases, rows and
  metrics are unchanged by the fix.
* The scorer was fixed and the run re-scored from the unchanged rows, so only
  `metrics.json` and `REPORT.md` changed. Matching is now one-way (a reported
  parent directory no longer earns credit); a positive case needs a true
  positive; an error, a missing row or an incomplete scan never earns a true
  negative; code keys outside the fact taxonomy are counted apart instead of
  as false positives; and results must be vouched for by the run manifest.
  Against the earlier `metrics.json`, ShadowScan's estate recall went from
  622 to 619 of 738, its in-scope F1 from 83% to 82% and its decoy
  specificity from 75% to 64%; AgentDiscover's code F1 went from 13% to 37%.
* The scorer then stopped crediting ShadowScan with true negatives for
  decoys its adapter never passes to it: the 17 IAM-role decoys of 15
  aws-export cases (see Withheld decoys under Metrics). Re-scored from the
  unchanged rows, ShadowScan's in-scope decoy specificity is 63% (421 of
  668; it was 64%, 438 of 685), its aws-export specificity 96% (46 of 48;
  was 97%, 63 of 65) and its cloud specificity still 98% (114 of 116; was
  131 of 133). Its agent false-alarm rate is 18% of 907 entities (was of
  924), 12% on cloud (was 11%). No case-level outcome changed, since every
  negative aws-export case also holds decoys ShadowScan is given.
* `verify --regenerate` had inferred a per-surface count of 38 for the
  committed corpus, rebuilt a smaller corpus and reported a difference,
  although the code still builds the committed cases. It now infers 40 and
  compares the parsed case lists. Plain `verify` (without `--regenerate`)
  exited 0 whenever the recorded generator digest matched, without looking
  at the cases, so a corpus whose truth was edited consistently passed; it
  now always rebuilds and compares the cases.
* The runner, the stage and the adapters were hardened for future runs: tools
  now run as uid 65534 with `/root` and `/home` hidden, and adapters fail
  closed on partial or malformed output. The committed rows were recorded
  before these changes. In that run the tools and the inert processes ran as
  root, in fresh network and PID namespaces with their own `/proc` but the
  host's file system otherwise in view, `/root` and `/home` included. Fleet's
  table, which also reads `/home/*` and `/root`, therefore saw the host's
  homes; its adapter kept only rows under the case home.
* The runner now records in `manifest.json` the harness commit and whether
  anything under `tools/` differed from it, and the report names both. It
  records the `version` that `tools.json` gives any tool; before, the Numbat,
  vet, AI-Infra-Guard and Fleet adapters always probed their binaries and
  ignored the version `install_tools.sh` wrote for them. It also refuses to
  start, with a message, when `gcc` cannot build the inert process binary,
  where it used to stop with a traceback. The 2026-10-11 manifest predates
  the harness fields, so its report names no harness commit and re-renders
  unchanged.

### The 2026-10-11 run, in brief

Each tool ran only on the cases of the surfaces and modalities it declares
([`results/2026-10-11/REPORT.md`](results/2026-10-11/REPORT.md)):

| Tool | Cases run | Surfaces and modalities |
|---|---|---|
| ShadowScan | 326 | all nine surfaces; on network, passive only (the 20 active cases were not run) |
| `agent-discovery` (Microsoft) | 86 | code, endpoint, runtime (live) |
| AgentDiscover | 66 | code, endpoint |
| SafeDep vet | 66 | code, endpoint |
| Fleet `ai_tools` table | 60 | endpoint, runtime (live) |
| Snyk Agent Scan | 40 | endpoint |
| Cisco MCP Scanner | 40 | endpoint |
| Numbat | 40 | endpoint |
| AI-Infra-Guard | 20 | network (active) |

No run crashed or timed out, and no row is missing. The numbers below are from
the fixed scorer. Read them with the caveats above: the rubrics are the
author's, and ShadowScan is the only tool whose maintainer also wrote the
corpus, the scorer and every other tool's adapter. They describe behaviour on
these inputs, not field accuracy, and they are not a verdict on any vendor's
product.

* **ShadowScan.** Estate recall 84% (619 of 738); in-scope entity precision,
  recall and F1 78%, 88% and 82% (F1 interval 80–85%); specificity on decoys
  63% (421 of 668), leaving out the 17 IAM-role decoys its adapter never
  passes to it. Specificity by surface: cloud 98%, low-code 91%, identity
  57%, runtime 45%, SaaS 33%; its other surfaces have no decoys in the cases
  it ran. Its weak points are where the rubric and its design disagree. It
  reports non-AI service identities (sync, backup, SCIM, Terraform and audit
  apps, managed identities)
  and the *MCP Partner Center* name decoy (69 identity false positives), every
  non-AI Slack app (53 of 53 Slack decoys), and classic topic-only Copilot
  Studio bots (11 Power Platform false positives). All 17 of its runtime false
  positives are a `gemini` crypto-exchange CLI taken for Gemini CLI. It missed
  three Entra Agent ID objects, Langflow and OpenClaw images on Kubernetes,
  Bedrock knowledge bases, and 17 processes whose only evidence is a `--model`
  flag. It marked 27 of its own scans incomplete: all 20 live-runtime cases
  and 7 code checkouts. Incomplete scans earn no true negatives, so its
  live-runtime specificity is 0% (none of 81 decoys credited, 7 flagged),
  against 88% on runtime snapshots.
* **Endpoint** (24 expected artifacts in 40 homes). ShadowScan found 17 with no
  false positive, Fleet's table 9 (2 false positives), SafeDep vet 8 (39),
  Snyk Agent Scan 7 (0), `agent-discovery` 4 (2), and AgentDiscover, Cisco MCP
  Scanner and Numbat 1 each with none. Numbat named the client directory in
  three homes, but only OpenClaw's state directory is an expected key there;
  `.codex` and `.config/goose` are tolerated and earn no credit. Cisco's Linux
  path table covers Cursor, Windsurf and VS Code only. vet reported the
  `.vscode` directory as a coding agent in all 40 homes, 39 of them false
  positives; its endpoint case recall is 33% and its case specificity 0%.
* **Active network** (32 AI services, 50 decoys). AI-Infra-Guard found 26 and
  flagged no decoy (specificity 100%; see the mock-service limit above). It
  missed Flowise (5 services) and one Open WebUI. Its *AI-Agent-Config*
  fingerprint, which the adapter maps to `agent`, fired on every vLLM, TGI and
  LiteLLM service, giving 11 agent false alarms out of 65.
* **Live runtime** (48 expected processes in 20 cases). `agent-discovery`
  found 6 (three MCP servers and three agent-framework runs) and Fleet's table
  5 (MCP servers only), both with no false positive. Neither recognised a
  coding-agent CLI, an AI editor or a model server from its command line.
* **Code** (109 expected facts in 26 repositories). Fact-level F1: ShadowScan
  94% (99 true positives, 3 false positives), AgentDiscover 37% (25, 1), vet
  15% (9, 0), `agent-discovery` 9% (5, 0). AgentDiscover's adapter passed on
  246 file-path keys and `agent-discovery`'s one; they are outside the fact
  taxonomy and are counted apart, not as false positives. The earlier brief's
  247 AgentDiscover false positives were these 246 keys and the one fact
  above.
* **Paired comparison** with ShadowScan on shared cases (cases only ShadowScan
  got right, against cases only the other tool got right): AgentDiscover 22
  against 1 (66 cases), vet 35 against 1 (66), `agent-discovery` 34 against 9
  (86), Cisco MCP Scanner and Numbat 16 against 0 (40 each), all p < 0.001;
  Snyk Agent Scan 10 against 0 (40), p = 0.002; Fleet's table 22 against 11
  (60), p = 0.080, not significant at 0.05. AI-Infra-Guard shares no case with
  ShadowScan, so it has no test. These tests measure agreement with the
  author's rubric on the author's corpus.
