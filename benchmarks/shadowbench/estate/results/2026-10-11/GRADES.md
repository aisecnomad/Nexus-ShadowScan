# ShadowBench tool grades — run 2026-10-11

An editorial ranking of the tools in this run, written by the same session
that authored the corpus and the harness. The grades layer judgment on top
of [`metrics.json`](metrics.json) and [`REPORT.md`](REPORT.md); the
numbers are reproducible, the letter grades are not. The benchmark is not
independent (see the [benchmark README](../../README.md)), and ShadowScan
is the repository's own tool: read its grade with that conflict of
interest in mind.

**Rubric** — in-scope effectiveness 50% (precision/recall/F1 on the
surfaces the tool declares), estate coverage 25% (how much of the
nine-surface problem it addresses at all), false-positive discipline 15%
(behavior on the 50 controls and near-misses), operability 10% (runs
offline without executing discovered content, machine-readable output,
speed). Grades judge each tool on this corpus and this operating model;
the per-surface F1 matrix in the report is the fairest single citation.

| # | Tool | Grade | In-scope value F1 | Estate-wide recall |
|---|---|---|---|---|
| 1 | ShadowScan (Project Nexus) 0.1.2 | A− | 93% | 95% |
| 2 | Snyk Agent Scan (mcp-scan) 0.6.8 | B− | 64% | 9% |
| 3 | SafeDep vet 1.20.0 | C+ | 43% | 12% |
| 4 | AgentDiscover 2.9.5 | C+ | 52% | 8% |
| 5 | AI-Infra-Guard 4.6.5 | C+ | 50% | 2% |
| 6 | Numbat 0.2.0 | C− | 35% | 4% |
| 7 | Agentic Radar 0.14.1 | D | 16% | 2% |
| 8 | AgentSight 1.0.34 (local sessions) | D / Incomplete | 10% | 1% |
| 9 | Cisco MCP Scanner 4.8.6 | F* | n/a | 0% |
| — | power-pwn 6.0.0 · Cartography 0.143.0 | Incomplete | n/a | n/a |

## Rationale

1. **ShadowScan — A−** *(conflict of interest: graded in its own
   repository by its own maintainer's session).* The only estate-wide
   system: 83/87 entities, 92/95/93% in-scope value P/R/F1, and the only
   registry reconciliation (83/83 shadow-vs-registered verdicts correct;
   79 shadow, 4 registered). Perfect on endpoint, network and runtime.
   Docked for flagging 8 of the deliberate traps (name-based recall at
   precision's expense) and for missing all four hard positives, which
   share one shape: self-hosted inference behind undocumented idioms.
2. **Snyk Agent Scan — B−** (B+ at its specialty). Flawless on MCP client
   configurations — every client and both MCP server identities, 100%
   precision — with the best safety posture in the field: its consent
   model inventories servers without executing anything. But "endpoint"
   for it means MCP configs; model stores, IDE and browser extensions and
   every offline export are out of reach (10 of 19 endpoint entities).
3. **SafeDep vet — C+** (breadth award). The only third-party tool on two
   surfaces; endpoint inventory nearly matches Snyk's, plus code-repo
   agent/MCP configs, at 0.2 s per unit. Capped by configs-only code
   coverage (3/23 code facts) and two wrong-fact predictions.
4. **AgentDiscover — C+** (best third-party code recall). Detected 5 of 6
   positive repositories — missing only the pure-IaC repo — and flagged
   zero negatives on this corpus. Facts are coarse (35% value recall) and
   single-surface; its offline k8s/CloudTrail layers could not be
   exercised here.
5. **AI-Infra-Guard — C+** (narrow, perfect within reach). Fingerprinted
   2/2 network-reachable services with exact versions and CVE context in
   about 2 s. Its 33% in-scope recall is a scoping statement: four of six
   runtime entities (stdio MCP servers, CLI agents) are invisible to any
   network scanner. Would rank higher on an internet-facing estate.
6. **Numbat — C−**. Found exactly the four agents with at-rest session
   transcripts, 100% precision, fastest tool in the field. It is a
   usage-forensics tool graded on an inventory rubric; it ignores
   config-only installs by design.
7. **Agentic Radar — D**. 2 of 6 positive repos, 9% in-scope value
   recall, slowest per unit. Consistent with its 5% value recall on this
   repository's 87-repo code-surface benchmark: it detects only textbook
   framework layouts.
8. **AgentSight — D in this mode, Incomplete for its thesis**. The
   local-session fallback found 1/19 endpoint entities. Its primary eBPF
   runtime capture was environment-blocked (fentry/fexit BPF loads return
   EPERM on this kernel), so this grade covers the fallback, not the
   design. Do not generalize it.
9. **Cisco MCP Scanner — F\* (deliberately so)**. Zero detections because
   it enumerates MCP servers only by launching or connecting to them, and
   the benchmark never executes corpus content. That is the finding: it
   is a tool-content analyzer for live MCP servers, not a discovery tool.
   On a question like "are this running server's tools poisoned," this
   benchmark says nothing about it.

**power-pwn and Cartography — Incomplete, not F.** Both require live
estates by design (interactive Microsoft 365/MSAL tenant authentication;
live cloud and AI-provider APIs synced into a running Neo4j). An offline
corpus cannot measure them, and they address the two surfaces — low-code
and SaaS tenants, cloud identity graphs — where offline open-source
options are weakest.

## One-sentence read

On this corpus the field splits into one estate-wide system (graded with
the home-team asterisk), precise single-surface specialists covering 2–12%
of the estate each, and tools whose operating model an offline,
no-execution benchmark structurally punishes — so cite the per-surface
matrix, not any single ranking.

A rendered PDF of the report and these grades is committed alongside as
[`ShadowBench-Report-2026-10-11.pdf`](ShadowBench-Report-2026-10-11.pdf).
