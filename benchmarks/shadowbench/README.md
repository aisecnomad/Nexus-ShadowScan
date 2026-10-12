# ShadowBench

The nine-surface shadow AI agent discovery benchmark, in two tracks. Both ask
the same question of the same tools and report precision, recall and F1 per
tool and per surface; they differ in where the ground truth comes from.

| Track | Ground truth | Size | Read |
|---|---|---|---|
| [`synthetic/`](synthetic/README.md) | Rubrics the maintainers wrote, from which a seeded generator writes platform-native inputs with entity-level truth, tolerated keys and decoys; the code surface reuses 26 pinned public repositories of the [code-surface benchmark](../shadow-ai-discovery/README.md) | 346 cases, 738 expected entities, 735 decoys | rubrics, bias controls, limits and the newest `results/*/REPORT.md` |
| [`estate/`](estate/README.md) | Authored artifacts of one fictional organization, Vantor Logistics, frozen by SHA-256, with every entity (positive, control, near-miss) anchored to unique tokens inside them | 137 labeled entities across 139 artifact files | protocol, label-completeness audit, bias and limits, and the newest `results/*/REPORT.md` |

The harness for both is [`tools/shadowbench/`](../../tools/shadowbench/README.md)
(`python -m tools.shadowbench <track> <command>`). Nothing here is a release
artifact, and neither track is independent review: the same maintainer wrote
ShadowScan, the harnesses, the rubrics and the labels. Treat every number as
offline evidence about the listed inputs, not as measured field precision or
recall, until someone without a stake reruns a track with their own seed,
families or estate.
