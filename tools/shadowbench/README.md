# ShadowBench harness

The harness for [ShadowBench](../../benchmarks/shadowbench/README.md), the
nine-surface shadow AI agent discovery benchmark. Read that page first: it
explains the two tracks, what each can show and why neither is independent.

| Track | Package | Commands (`python -m tools.shadowbench <track> <command>`) | Design and results |
|---|---|---|---|
| Cases | [`cases/`](cases/README.md) | `generate`, `verify`, `run`, `score`, `report` | [benchmarks/shadowbench/cases/](../../benchmarks/shadowbench/cases/README.md) |
| Estate | [`estate/`](estate/) | `validate`, `freeze`, `verify-freeze`, `run`, `score`, `report` | [benchmarks/shadowbench/estate/](../../benchmarks/shadowbench/estate/README.md) |

Each track keeps its own corpus model, adapters, runner and scorer; nothing is
shared between them except the code-surface helpers both reuse from
[`tools/discovery_benchmark/`](../discovery_benchmark/README.md). Unit tests
live in `tests/unit/test_shadowbench*.py`.

Running third-party tools executes their code on your machine. Do it only on
a disposable, externally isolated host with no credentials, at the versions
each track's README lists. Scoring and reporting a committed run need no
third-party tool.
