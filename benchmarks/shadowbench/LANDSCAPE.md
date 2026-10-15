# ShadowBench: open-source landscape and real-world corpus footprint

ShadowBench lives in this repository
([aisecnomad/Nexus-ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan))
and asks one question on the nine surfaces where shadow AI agents leave
evidence: *given what an operator can collect, which AI agents and plain AI
uses can a discovery tool find, and at what false-positive cost?* It answers
from two tracks ([Cases](cases/README.md) and [Estate](estate/README.md)) and
runs an adapter per third-party tool so the harness can be rerun by anyone
on a disposable, externally isolated host.

This page is a reader's map. It is not a leaderboard: it does not add
measured precision or recall beyond what each track's results already
publish, and it does not endorse any vendor product. The track-level
results, metrics and their intervals are in each track's README.

> **Read this first.** The same maintainer wrote ShadowScan, both corpora,
> every label, and every adapter. On eight of nine surfaces the inputs are
> synthetic because no public source of real tenant, gateway, endpoint or
> process data exists at this scale; only the code surface uses real public
> repositories. Any ShadowScan lead is suspect until someone without a stake
> reruns the benchmark on their own corpus. Each track's README has the full
> caveats, including the in-sample estate note from the 2026-10-11 run; this
> page restates them so a casual reader cannot miss them.

## Current scope

| Track | Inputs | Expected entities | Decoys | Harness |
|---|---|---|---|---|
| [Cases](cases/README.md) | 346 cases: 320 generated from written rubrics on eight surfaces, plus 26 public repositories pinned by commit on the code surface | 738 | 735 | [`tools/shadowbench/cases/`](../../tools/shadowbench/cases/) |
| [Estate](estate/README.md) | 139 frozen files for one authored fictional organization (Adatum Logistics) on all nine surfaces | 137 (87 positive, 27 control, 23 near-miss) | — | [`tools/shadowbench/estate/`](../../tools/shadowbench/estate/) |

## Real public repositories in the broader project

Code is the one surface where real public artifacts exist at scale. Across
this repository, three real-repo corpora are kept pinned by 40-character
commit SHAs, each with per-item class, languages, size, expected facts and
tolerated facts:

| Corpus | Real repos | Where |
|---|---|---|
| ShadowBench code-surface cases | 26 (GitHub) | [`cases/corpus.json`](cases/corpus.json) |
| Shadow AI discovery (code surface) | 87 (84 GitHub + 3 GitLab) | [`../shadow-ai-discovery/corpus.json`](../shadow-ai-discovery/corpus.json) |
| Sampled real-world repositories | 326 random/purposive GitHub + GitLab samples | [`tools/benchmark/realworld/`](../../tools/benchmark/realworld/) |
| Earlier real-world cohort | 34 | [`../realworld/`](../realworld/README.md) |

The three code-surface sets overlap by design: `shadow-ai-discovery/` is the
labeling source, and ShadowBench embeds a subset of it as the code-surface
cases.

## Open-source shadow AI agent discovery tools and ShadowBench adapters

The table below maps the open-source "shadow AI agent discovery" projects a
reader is likely to encounter today onto ShadowBench's adapter inventory.
The adapter column names which ShadowBench adapter (if any) runs the
project. *Not verified here* means the project appeared in public search
summaries but was not inspected, installed or exercised in this repository;
its presence or absence from ShadowBench is not a statement about the
project's quality.

| Project | ShadowBench adapter | Surfaces (per adapter) | Notes |
|---|---|---|---|
| ShadowScan ([this repo](https://github.com/aisecnomad/Nexus-ShadowScan)) | [`shadowscan.py`](../../tools/shadowbench/cases/adapters/shadowscan.py), [`shadowscan_estate.py`](../../tools/shadowbench/estate/adapters/shadowscan_estate.py) | all nine; network passive only in cases | author of this benchmark; see conflict-of-interest note |
| Microsoft Agent Governance Toolkit (`agent-discovery`) | [`agentmesh_discovery.py`](../../tools/shadowbench/cases/adapters/agentmesh_discovery.py) | code, endpoint, runtime (live) | Microsoft toolkit's discovery component |
| SafeDep vet (`vet ai discover`) | [`vet.py`](../../tools/shadowbench/cases/adapters/vet.py) | code, endpoint | `--scope project` and `--scope system` |
| AgentDiscover Scanner | [`agentdiscover.py`](../../tools/shadowbench/cases/adapters/agentdiscover.py) | code, endpoint | layers 2–5 skipped offline |
| AI-Infra-Guard (Tencent) | [`ai_infra_guard.py`](../../tools/shadowbench/cases/adapters/ai_infra_guard.py) | network (active) | run against loopback mock services |
| Fleet `ai_tools` table (fleetdm/fleet) | [`fleet_ai_tools.py`](../../tools/shadowbench/cases/adapters/fleet_ai_tools.py) | endpoint, runtime (live) | the osquery table only, compiled into a tiny Go program |
| Snyk Agent Scan | [`snyk_agent_scan.py`](../../tools/shadowbench/cases/adapters/snyk_agent_scan.py) | endpoint | included to triangulate the open-source rows; not open source |
| Cisco MCP Scanner | [`cisco_mcp_scanner.py`](../../tools/shadowbench/cases/adapters/cisco_mcp_scanner.py) | endpoint | same |
| Numbat (Perplexity) | [`numbat.py`](../../tools/shadowbench/cases/adapters/numbat.py) | endpoint | same |
| AgentSight | not run | — | eBPF uprobes on live TLS libraries; no offline entry |
| Cartography (Lyft) | not run | — | needs Neo4j and live cloud APIs |
| Copilot Studio Kit Agent Inventory (Microsoft) | not run | — | Power Platform solution, no offline entry |
| google/k8s-aibom | not run | — | in-cluster controller; no manifest mode |
| `saagpatel/shadow-mcp` | not verified here | would be endpoint, runtime | local-first OWASP MCP09 shadow-server inventory |
| `themsquared/shadow-mcp-scanner` | not verified here | would be network | network-side MCP server discovery |
| `Defend-AI-Tech-Inc/agent-discover-scanner` | not verified here | — | not confirmed to be the same project as AgentDiscover above |
| `mizcausevic-dev/shadow-ai-detector` | not verified here | would be endpoint, network | 30+ provider egress scanner |
| `backslash-security/Claw-Hunter` | not verified here | would be endpoint | MDM-ready endpoint scripts |
| `knostic/AgentSonar` | not verified here | would be network | process-to-domain traffic classification |
| `aurva-io/AIOstack` | not verified here | would be runtime | runtime inventory |
| `alebgl77/open-shadow-ai` | not verified here | would span network, endpoint, identity | README still marks components "pending validation" |

Adding an adapter for a *not verified here* project is work: it needs the
project installed at a pinned version on a disposable host, calibrated on a
smoke corpus (never the scored one), and documented in the adapter's
docstring the way the existing adapters are. Pull requests that add one are
welcome; see the harness READMEs for the contract. The project list here
comes from public search in October 2026 and will go stale.

## Toward a 450-item code-surface corpus

The question "ShadowBench with 450 real-world items, no synthetic" has one
honest path: add real public repositories to the code surface. The other
eight surfaces have no public tenant, gateway, endpoint or process corpus
of comparable scale, so growing them further would mean more synthetic
data (clearly segregated in `estate/` and in the generated cases) rather
than real-world items.

The shortest route is to extend
[`../shadow-ai-discovery/corpus.json`](../shadow-ai-discovery/corpus.json)
with more pinned public repositories (the code-surface benchmark that feeds
ShadowBench's code cases) along the categories that benchmark already
labels: agent frameworks, MCP servers, MCP client configurations,
coding-agent configuration surfaces, A2A agent cards, low-code AI flows,
and infrastructure as code for managed AI resources. New entries follow the
same shape as the existing 87 (`id`, `host`, `path`, `commit`, `class`,
`languages`, `size_kb`, `file_count`, `expected`, `tolerated`, `notes`).

Any such extension still carries the same caveat as the existing corpus:
labels are session-labeled evidence written in this repository, not
independent review. A test for overfitting is to regenerate ShadowBench's
cases at a fresh seed under the `sha256` stream scheme (not `legacy`),
which draws different cases from the same families on eight surfaces, and
to rerun every adapter.

## Caveats, restated

- **Conflict of interest.** The same maintainer wrote ShadowScan, both
  ShadowBench tracks, every corpus, every label and every adapter.
- **Synthetic data on eight surfaces.** Real tenants are messier, larger
  and have more kinds of records. The committed rubrics encode the
  author's view of what evidence suffices.
- **In-sample runs on the estate.** ShadowScan's detection rules were
  changed after the 2026-10-11 estate run with that run's errors in view.
  A ShadowScan run on the estate after those changes says nothing new
  about field accuracy; only a new, independently authored estate can.
- **Not a verdict on any vendor.** The results show how each tool behaves
  on these inputs. They are not an independent evaluation and are not
  field precision or recall. No letter grades are published.
- **Commercial adapters.** Snyk Agent Scan, Cisco MCP Scanner and Numbat
  are included to triangulate the open-source rows, not because they are
  open source.
- **No independent review.** Scorecard, CI, CodeQL, and files under
  `archive/reviews/` are not independent human review. See
  [AGENTS.md](../../AGENTS.md) for the project's hard rules on evidence
  and offline corpora.
