"""Nine-surface shadow AI agent discovery estate benchmark harness.

The estate benchmark generalizes the code-surface discovery benchmark
(`tools/discovery_benchmark/`) from pinned repositories to a fictional
organization's full artifact estate: code checkouts, identity-provider
exports, gateway logs, low-code platform exports, SaaS app inventories,
cloud inventories, endpoint home trees and offline endpoint exports,
network logs and runtime process exports.

Ground truth is a set of labeled *entities* (positive, control, near-miss),
each anchored to unique tokens inside the artifacts, so true positives,
false positives, true negatives and false negatives are all countable.
The corpus, the protocol and the committed results live in
`benchmarks/shadowbench/estate/`. Nothing here is a release artifact, and the
results are not independent: the same maintainer wrote ShadowScan, the
harness and the labels.
"""
