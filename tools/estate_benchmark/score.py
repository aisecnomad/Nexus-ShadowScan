"""Score estate runs against the corpus.

Attribution: a prediction is attributed to the entity whose anchor appears
in the prediction's text (case-insensitive substring), preferring the
longest matching anchor; when no anchor matches but the prediction's run
unit is a unit that exactly one entity set claims, it stays unattributed.
Scoring then mirrors the code-surface benchmark:

- value level: exact facts, with `<category>:generic` consuming one expected
  fact of its category; tolerated facts are dropped before scoring; facts a
  tool reports outside the taxonomy never reach the scorer (adapters drop
  them).
- entity level: a positive is detected when any attributed in-scope
  prediction matches an expected fact; a control or near-miss is flagged by
  any attributed in-scope prediction. Unflagged negatives are true
  negatives.
- unattributed in-scope predictions are charged as false positives at value
  level, and reported.
- the shadow layer scores registry reconciliation for tools that emit a
  shadow verdict: detected registered entities should read registered
  (shadow false), detected unregistered positives should read shadow.

In-scope counts only a tool's declared surfaces; the estate-wide number
charges every tool for every expected fact on every surface.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import median
from typing import Any

from tools.estate_benchmark import taxonomy
from tools.estate_benchmark.corpus import Entity, EstateCorpus

_ROUND = 4


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        total = self.tp + self.fp
        return round(self.tp / total, _ROUND) if total else None

    @property
    def recall(self) -> float | None:
        total = self.tp + self.fn
        return round(self.tp / total, _ROUND) if total else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None if p is None or r is None else 0.0
        return round(2 * p * r / (p + r), _ROUND)

    def add(self, other: Counts) -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


def match_values(predicted: set[str], expected: frozenset[str]) -> Counts:
    """Exact matches first; a `<cat>:generic` consumes one expected fact of
    its category; surplus generics on a present category are never charged."""
    counts = Counts()
    remaining = set(expected)
    for fact in sorted(predicted & remaining):
        counts.tp += 1
        remaining.discard(fact)
    for fact in sorted(predicted - expected):
        cat, _, value = fact.partition(":")
        if value == taxonomy.GENERIC:
            of_category = sorted(item for item in remaining if item.startswith(f"{cat}:"))
            if of_category:
                counts.tp += 1
                remaining.discard(of_category[0])
                continue
            if any(item.startswith(f"{cat}:") for item in expected):
                counts.tp += 1
                continue
            counts.fp += 1
            continue
        counts.fp += 1
    counts.fn = len(remaining)
    return counts


@dataclass
class Attribution:
    entity_predictions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    unattributed: list[dict[str, Any]] = field(default_factory=list)


def attribute(corpus: EstateCorpus, predictions: list[dict[str, Any]]) -> Attribution:
    """Attribute predictions to entities.

    First by anchor (longest match wins). A prediction from a unit-bound run
    (`code:<repo>`, `home:<device>`) whose text carries no anchor falls back
    to the entity of that unit whose expected facts contain the predicted
    fact (exactly, or by category for a `generic` value) — inventory tools
    echo client names, not the corpus's anchors. Everything else is
    unattributed and charged as a false positive.
    """
    anchors: list[tuple[str, Entity]] = []
    for entity in corpus.entities:
        for anchor in entity.anchors:
            anchors.append((anchor, entity))
    anchors.sort(key=lambda item: -len(item[0]))
    tolerated = [(item.fact, item.anchor) for item in corpus.tolerated_global]
    by_unit: dict[str, list[Entity]] = defaultdict(list)
    for entity in corpus.entities:
        by_unit[entity.unit].append(entity)
    result = Attribution(entity_predictions={e.id: [] for e in corpus.entities})
    for prediction in predictions:
        text = str(prediction.get("text", "")).lower()
        fact = str(prediction.get("fact", ""))
        if any(fact == t_fact and t_anchor in text for t_fact, t_anchor in tolerated):
            continue
        owner: Entity | None = None
        for anchor, entity in anchors:
            if anchor in text:
                owner = entity
                break
        unit = str(prediction.get("unit", "estate"))
        if owner is None and unit != "estate":
            cat = taxonomy.category(fact) if ":" in fact else ""
            generic = fact.endswith(f":{taxonomy.GENERIC}")
            candidates = [
                entity
                for entity in by_unit.get(unit, [])
                if fact in entity.expected_facts
                or (generic and any(f.startswith(f"{cat}:") for f in entity.expected_facts))
            ]
            if len(candidates) == 1:
                owner = candidates[0]
        if owner is None:
            result.unattributed.append(prediction)
        else:
            result.entity_predictions[owner.id].append(prediction)
    return result


def _in_scope(prediction: dict[str, Any], surfaces: frozenset[str]) -> bool:
    return str(prediction.get("surface", "")) in surfaces


def score_tool(
    corpus: EstateCorpus,
    tool_id: str,
    surfaces: frozenset[str],
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = [row for row in runs if row.get("tool") == tool_id]
    predictions = [
        {**dict(p), "unit": row.get("unit", "estate")} for row in rows for p in row.get("predictions", [])
    ]
    attribution = attribute(corpus, predictions)

    value_in_scope = Counts()
    value_all = Counts()
    by_surface: dict[str, Counts] = {surface: Counts() for surface in taxonomy.SURFACES}
    entity_rows: dict[str, dict[str, Any]] = {}
    detected = flagged_controls = flagged_nearmiss = 0
    positives = len(corpus.by_class("positive"))
    controls = len(corpus.by_class("control"))
    nearmisses = len(corpus.by_class("nearmiss"))
    shadow_expected = shadow_correct = 0

    for entity in corpus.entities:
        attributed = attribution.entity_predictions[entity.id]
        scoped = [p for p in attributed if _in_scope(p, surfaces)]
        facts_scoped = {str(p["fact"]) for p in scoped} - set(entity.tolerated)
        facts_all = {str(p["fact"]) for p in attributed} - set(entity.tolerated)
        scoped_counts = match_values(facts_scoped, entity.expected_facts)
        all_counts = match_values(facts_all, entity.expected_facts)
        if entity.surface in surfaces:
            value_in_scope.add(scoped_counts)
        by_surface[entity.surface].add(all_counts)
        value_all.add(all_counts)
        entity_detected = entity.klass == "positive" and scoped_counts.tp > 0
        entity_flagged = entity.klass != "positive" and bool(facts_scoped)
        if entity_detected:
            detected += 1
        if entity_flagged and entity.klass == "control":
            flagged_controls += 1
        if entity_flagged and entity.klass == "nearmiss":
            flagged_nearmiss += 1
        verdicts = [p.get("shadow") for p in attributed if p.get("shadow") is not None]
        if entity.klass == "positive" and verdicts and scoped_counts.tp > 0:
            shadow_expected += 1
            wants_shadow = not entity.registered
            if all(v is wants_shadow for v in verdicts):
                shadow_correct += 1
        entity_rows[entity.id] = {
            "class": entity.klass,
            "surface": entity.surface,
            "detected": entity_detected,
            "flagged": entity_flagged,
            "tp": scoped_counts.tp,
            "fp": scoped_counts.fp,
            "fn": scoped_counts.fn,
        }

    unattributed_scoped = [p for p in attribution.unattributed if _in_scope(p, surfaces)]
    value_in_scope.fp += len(unattributed_scoped)
    value_all.fp += len(attribution.unattributed)

    entity_counts = Counts(tp=detected, fp=flagged_controls + flagged_nearmiss, fn=positives - detected)
    true_negatives = (controls + nearmisses) - (flagged_controls + flagged_nearmiss)
    statuses: dict[str, int] = defaultdict(int)
    for row in rows:
        statuses[str(row.get("status", "missing"))] += 1
    seconds = sorted(float(row.get("seconds", 0.0)) for row in rows)
    incomplete_units = sorted(str(row.get("unit")) for row in rows if row.get("incomplete"))

    return {
        "runs": dict(statuses),
        "units": len(rows),
        "incomplete_units": incomplete_units,
        "seconds": {
            "median": round(median(seconds), 2) if seconds else None,
            "max": round(seconds[-1], 2) if seconds else None,
            "total": round(sum(seconds), 2),
        },
        "entity_level": {
            **entity_counts.to_dict(),
            "tn": true_negatives,
            "positives": positives,
            "positives_detected": detected,
            "controls": controls,
            "controls_flagged": flagged_controls,
            "nearmiss": nearmisses,
            "nearmiss_flagged": flagged_nearmiss,
        },
        "value_level": {
            "in_scope": value_in_scope.to_dict(),
            "all": value_all.to_dict(),
            "by_surface": {surface: counts.to_dict() for surface, counts in by_surface.items()},
        },
        "shadow_layer": {
            "scored": shadow_expected,
            "correct": shadow_correct,
        },
        "unattributed": [
            {"fact": p.get("fact"), "text": str(p.get("text", ""))[:160]}
            for p in attribution.unattributed[:50]
        ],
        "per_entity": entity_rows,
    }


def score_all(
    corpus: EstateCorpus,
    manifest: dict[str, Any],
    specs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    runs = list(manifest.get("results", []))
    expected_by_surface: dict[str, int] = defaultdict(int)
    for entity in corpus.by_class("positive"):
        expected_by_surface[entity.surface] += len(entity.expected)
    tools: dict[str, Any] = {}
    for tool_id, spec in specs.items():
        if tool_id in manifest.get("tools_skipped", {}):
            continue
        surfaces = frozenset(str(s) for s in spec.get("surfaces", []))
        tools[tool_id] = {
            "name": spec.get("name", tool_id),
            "version": manifest.get("tool_versions", {}).get(tool_id, "unknown"),
            "surfaces": sorted(surfaces),
            **score_tool(corpus, tool_id, surfaces, runs),
        }
    return {
        "corpus": {
            "entities": len(corpus.entities),
            "positive": len(corpus.by_class("positive")),
            "control": len(corpus.by_class("control")),
            "nearmiss": len(corpus.by_class("nearmiss")),
            "registered": sum(1 for e in corpus.entities if e.registered),
            "expected_facts": sum(len(e.expected) for e in corpus.entities),
            "expected_by_surface": dict(sorted(expected_by_surface.items())),
        },
        "run": {
            "started": manifest.get("started"),
            "finished": manifest.get("finished"),
            "policy": manifest.get("policy"),
            "workers": manifest.get("workers"),
            "tools_skipped": manifest.get("tools_skipped", {}),
        },
        "tools": tools,
    }
