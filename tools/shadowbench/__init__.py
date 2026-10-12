"""ShadowBench: nine-surface shadow AI agent discovery benchmarks.

Two tracks share the name and the question, and nothing else: each has its own
corpus model, adapters, runner and scorer.

* ``tools.shadowbench.cases``: seeded, generated, platform-native cases per
  surface, with decoys (``benchmarks/shadowbench/cases/``).
* ``tools.shadowbench.estate``: one authored fictional organization whose
  artifacts span all nine surfaces at once, scored entity by entity
  (``benchmarks/shadowbench/estate/``).

``python -m tools.shadowbench <track> <command>`` runs a track's command; see
``benchmarks/shadowbench/README.md`` for what each track can and cannot show.
Nothing here is a release artifact.
"""
