# ShadowBench

ShadowBench asks one question across all nine surfaces where shadow AI
agents leave evidence (code, identity, gateway, low-code, SaaS, cloud,
endpoint, network and runtime): *given what an operator can collect, which AI
agents and which plain AI uses can a discovery tool find, and at what
false-positive cost?* It answers from two directions, as two tracks that share
the name and the question but nothing else. Each track has its own corpus
model, adapters, runner and scorer.

> **Read this first.** ShadowBench is not independent. The same maintainer
> wrote ShadowScan, both harnesses, every corpus, every label and every
> adapter for the other tools. Every estate file is authored, and eight of
> the cases track's nine surfaces are synthetic; only its code cases are real
> public repositories. The results show how each tool behaves on these
> inputs. They are not field precision or recall, not an independent
> evaluation and not a verdict on any vendor's product, and no letter grades
> are published. A ShadowScan lead is suspect until someone without a stake
> reruns the benchmark, ideally with their own corpus. Everything needed to
> do that is committed. See [docs/evaluation.md](../../docs/evaluation.md) for
> what ShadowScan accepts as evidence.

## Two tracks

| | [Cases](cases/README.md) | [Estate](estate/README.md) |
|---|---|---|
| Question | Per surface and input type: does the tool find the expected entities in one platform-native input, and leave its decoys alone? | Across one organization's whole estate at once: which entities does the tool find, which controls and near-misses does it flag, and does it tell registered agents from shadow ones? |
| Inputs | 320 cases generated at a recorded seed from written rubrics on eight surfaces, plus 26 public repositories pinned by commit | One authored fictional organization, Adatum Logistics: repositories, home directories and vendor-format exports on all nine surfaces |
| Ground truth | Per-case entities labeled `agent` or `llm`, tolerated keys and decoys | 137 entities (87 positive, 27 control, 23 near-miss), each with facts, evidence pointers and anchors |
| Size | 346 cases, 738 expected entities, 735 decoys | 139 frozen files |
| Integrity check | `verify --regenerate` rebuilds the corpus from the generator at its seed | `verify-freeze` checks every file against `FREEZE.json` |
| Distinctive measurements | Wilson and bootstrap intervals, agent-tier recall, paired McNemar tests; loopback mock services and inert live processes for tools that only work live | Value-level and entity-level scoring with anchors, estate-wide recall, a registry layer that checks shadow-versus-registered classification |
| Harness | [`tools/shadowbench/cases/`](../../tools/shadowbench/cases/README.md) | [`tools/shadowbench/estate/`](../../tools/shadowbench/estate/) |
| Results | [`cases/results/`](cases/results/) | [`estate/results/`](estate/results/) |

The tracks were written independently (pull requests #193 and #194) and
integrated side by side. Their tool lists, versions and scoring rules differ,
so a tool's numbers on one track are not comparable with its numbers on the
other.

## Running a track

From the repository root, after `make install`:

```bash
python -m tools.shadowbench                      # list the tracks
python -m tools.shadowbench cases verify --corpus benchmarks/shadowbench/cases/corpus.json --regenerate
python -m tools.shadowbench estate validate
python -m tools.shadowbench estate verify-freeze
```

`python -m tools.shadowbench.cases` and `python -m tools.shadowbench.estate`
are the same entry points. Scoring a committed run needs nothing else
installed; running the third-party tools needs them installed at the versions
each track's README lists, on a disposable machine with no credentials.

## Integration errata

These changes were made when the two pull requests were integrated. Each
track's README and the changelog give the details.

- The tracks moved under `cases/` and `estate/`. The estate's authored files
  moved to `estate/artifacts/`, with every frozen digest unchanged.
- One estate file was never committed, because `.gitignore` excluded
  `.vscode/`. It was replaced and its digest updated, and a test now fails
  when any frozen file is untracked.
- The estate's fictional organization was renamed from *Vantor* (since 2025
  the name of a real company) to *Adatum*. The replacement has the same
  length, so re-scoring the renamed run gave identical results.
- The vendor letter grades and the PDFs were removed.
- Defects the review found in both scorers, runners and adapters were
  fixed, and both committed runs were re-scored with the fixed scorers. The
  rows the tools produced are unchanged; each track's README describes what
  moved.
