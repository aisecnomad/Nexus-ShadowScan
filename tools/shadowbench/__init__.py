"""ShadowBench: the nine-surface shadow AI agent discovery benchmark, in two tracks.

``synthetic`` (:mod:`tools.shadowbench.synthetic`) generates a seeded corpus of
platform-native inputs across the nine surfaces with entity-level truth, tolerated
keys and decoys; ``estate`` (:mod:`tools.shadowbench.estate`) scores tools against
the authored artifacts of one fictional organization, Vantor Logistics, whose
labeled entities are anchored to unique tokens inside those artifacts. The two
tracks ask the same question with different evidence: generated breadth at scale,
and an authored estate whose every artifact a person wrote and labeled.

Corpora, protocols and committed results live under ``benchmarks/shadowbench/``.
Nothing here is a release artifact, and the results are not independent review:
the same maintainer wrote ShadowScan, both harnesses, the rubrics and the labels.
"""
