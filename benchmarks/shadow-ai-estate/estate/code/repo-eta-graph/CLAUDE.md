# eta-graph

LangGraph service that replans linehaul ETAs.

- Run tests with `pytest -q`.
- The graph entry point is `eta_graph.graph.build_graph`.
- ETA drafts must keep the shipment id verbatim; dispatch matches on it.
- Never commit real telemetry exports; use the fixtures under `tests/`.
