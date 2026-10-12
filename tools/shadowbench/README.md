# ShadowBench harness

ShadowBench asks one question on every surface where shadow AI agents leave
evidence: given what an operator can collect from that surface, which AI agents
and AI uses are present, and can a discovery tool find them without flagging
what merely sounds like AI? It is answered in two tracks that share this
package and the `benchmarks/shadowbench/` directory:

| Track | Evidence | Harness | Corpus and results |
|---|---|---|---|
| `synthetic` | A seeded generator writes platform-native inputs on nine surfaces (346 cases, 738 expected entities, 735 decoys) with entity-level truth, tolerated keys and decoys; active-network and live-runtime cases run inside the tool's namespaces | [`synthetic/`](synthetic/README.md) | [`benchmarks/shadowbench/synthetic/`](../../benchmarks/shadowbench/synthetic/README.md) |
| `estate` | One authored, SHA-256-frozen estate of a fictional organization, Vantor Logistics: 137 labeled entities (positive, control, near-miss) anchored to unique tokens inside vendor-format artifacts across the nine surfaces | [`estate/`](estate/) | [`benchmarks/shadowbench/estate/`](../../benchmarks/shadowbench/estate/README.md) |

Every command takes the track first:

```bash
python -m tools.shadowbench synthetic {generate|verify|run|score|report|pdf} ...
python -m tools.shadowbench estate {validate|freeze|verify-freeze|run|score|report} ...
```

`python -m tools.shadowbench.synthetic ...` and `python -m tools.shadowbench.estate ...`
run a track on its own. Third-party tools run in isolation inside the harness,
which is not a filesystem sandbox: run either track only on a disposable,
externally isolated machine with no credentials.

Nothing here is a release artifact. Neither track is independent review: the
same maintainer wrote ShadowScan, both harnesses, the rubrics and the labels;
each track's README states its limits.
