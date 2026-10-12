"""Score estate runs against the corpus.

Attribution (`attribute`) gives each prediction at most one owning entity:

1. A prediction matching a corpus-level tolerated (fact, anchor) pair is
   dropped.
2. Candidates are the entities on the prediction's surface (its own
   `surface` field, or, when that is missing or unknown, the surfaces its
   fact's category lives on) that the prediction's run reaches. A
   whole-estate run reaches every entity; a unit-bound run (`code:<repo>`,
   `home:<device>`) reaches the entities of that unit and the estate-wide
   entities with an artifact inside the unit's tree, such as an MCP server
   configured in several home trees.
3. Among candidates whose anchor appears in the prediction's text
   (case-insensitive substring), entities that expect the predicted fact
   (exactly, or by category for a `generic` value) beat entities whose
   expected or tolerated facts share its category, which beat the rest.
   When more than one entity is left, the longest matching anchor and then
   the entity id pick the owner, and the prediction is counted and listed
   as ambiguous.
4. When no candidate's anchor matches and the run is unit-bound, the
   prediction falls back to the one candidate that expects the fact:
   inventory tools echo client names, not the corpus's anchors. With no
   such candidate, or several, it stays unattributed.

An attributed prediction takes its entity's surface, so it is in scope
exactly when the tool declares that surface; an unattributed prediction is
in scope when its own placement touches a declared surface (or cannot be
placed at all). Predictions outside the declared surfaces count in the
estate-wide numbers only and are reported as out of scope, never dropped.

Completeness: a run row is incomplete when its status is not `ok`, the
adapter flagged it incomplete, it recorded an error, or any of its commands
timed out or exited with a code the adapter did not declare as success
(the runner records that as the command's `ok`). A code or home unit the
corpus labels is missing for a tool that ran other units of that kind but
has no row for it, and a tool with no rows at all is missing everywhere.
Every entity an incomplete or missing run reaches is *unscored* for the
tool: its expected facts count as missed, a positive is not detected, and a
negative earns no true negative (a flag on it is still a false positive).
An incomplete run never reads as a clean negative. Non-zero exits an
adapter declares as success are counted and reported, not failed.

Scoring then mirrors the code-surface benchmark:

- value level: exact facts, with `<category>:generic` consuming one expected
  fact of its category; tolerated facts are dropped before scoring; facts a
  tool reports outside the taxonomy never reach the scorer (adapters drop
  them). Unattributed predictions are false positives.
- entity level, in scope: only entities on the tool's declared surfaces. A
  positive is detected when an attributed prediction matches an expected
  fact; a control or near-miss is flagged by any attributed prediction.
  Unflagged, scored negatives are true negatives.
- estate-wide: positives detected out of every positive, and value recall
  charged for every expected fact on all nine surfaces.
- the shadow layer scores registry reconciliation for tools that emit a
  shadow verdict: detected registered entities should read registered
  (shadow false), detected unregistered positives should read shadow.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import median
from typing import Any

from tools.shadowbench.estate import taxonomy
from tools.shadowbench.estate.corpus import Entity, EstateCorpus

_ROUND = 4
_UNIT_KINDS = ("code", "home")
MISSING_RUN = "no run recorded"


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
    its category. A surplus generic on a category that is expected but
    already fully matched is neither charged nor credited."""
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
                continue
        counts.fp += 1
    counts.fn = len(remaining)
    return counts


def unit_bound(unit: str) -> bool:
    """True for a run over one code repository or one home tree."""
    kind, sep, name = unit.partition(":")
    return bool(sep and name) and kind in _UNIT_KINDS


def reaches(unit: str, entity: Entity) -> bool:
    """True when a run over `unit` can see `entity`'s artifacts."""
    if not unit_bound(unit) or entity.unit == unit:
        return True
    if entity.unit != "estate":
        return False
    kind, _, name = unit.partition(":")
    return any(artifact.startswith(f"{kind}/{name}/") for artifact in entity.artifacts)


def placement(prediction: dict[str, Any]) -> frozenset[str]:
    """The surfaces a prediction can belong to: its own, else its category's."""
    surface = str(prediction.get("surface") or "")
    if surface in taxonomy.SURFACES:
        return frozenset({surface})
    fact = str(prediction.get("fact", ""))
    return taxonomy.category_surfaces(taxonomy.category(fact)) if ":" in fact else frozenset()


def _expects(entity: Entity, fact: str) -> bool:
    if fact in entity.expected_facts:
        return True
    cat, _, value = fact.partition(":")
    return value == taxonomy.GENERIC and any(taxonomy.category(f) == cat for f in entity.expected_facts)


def _preference(entity: Entity, fact: str) -> int:
    """0 expects the fact, 1 expects or tolerates its category, 2 neither."""
    if _expects(entity, fact):
        return 0
    cat = taxonomy.category(fact)
    if any(taxonomy.category(f) == cat for f in (*entity.expected_facts, *entity.tolerated)):
        return 1
    return 2


@dataclass
class Attribution:
    entity_predictions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    unattributed: list[dict[str, Any]] = field(default_factory=list)
    ambiguous: list[dict[str, Any]] = field(default_factory=list)
    tolerated: int = 0


def attribute(corpus: EstateCorpus, predictions: list[dict[str, Any]]) -> Attribution:
    """Attribute predictions to entities; the module docstring has the rules."""
    tolerated = [(item.fact, item.anchor) for item in corpus.tolerated_global]
    result = Attribution(entity_predictions={e.id: [] for e in corpus.entities})
    for prediction in predictions:
        text = str(prediction.get("text", "")).lower()
        fact = str(prediction.get("fact", ""))
        if any(fact == t_fact and t_anchor in text for t_fact, t_anchor in tolerated):
            result.tolerated += 1
            continue
        surfaces = placement(prediction)
        unit = str(prediction.get("unit", "estate"))
        reachable = [e for e in corpus.entities if e.surface in surfaces and reaches(unit, e)]
        ranked: list[tuple[int, int, str, Entity]] = []
        for entity in reachable:
            lengths = [len(anchor) for anchor in entity.anchors if anchor in text]
            if lengths:
                ranked.append((_preference(entity, fact), -max(lengths), entity.id, entity))
        owner: Entity | None = None
        if ranked:
            ranked.sort(key=lambda item: (item[0], item[1], item[2]))
            best = [item for item in ranked if item[0] == ranked[0][0]]
            owner = best[0][3]
            if len(best) > 1:
                result.ambiguous.append(
                    {
                        "fact": fact,
                        "text": str(prediction.get("text", ""))[:160],
                        "entity": owner.id,
                        "candidates": [item[2] for item in best],
                    }
                )
        elif unit_bound(unit):
            candidates = [entity for entity in reachable if _expects(entity, fact)]
            if len(candidates) == 1:
                owner = candidates[0]
        if owner is None:
            result.unattributed.append(prediction)
        else:
            result.entity_predictions[owner.id].append(prediction)
    return result


def incomplete_reason(row: dict[str, Any]) -> str | None:
    """Why a run row is not a complete run, or None when it is."""
    status = row.get("status")
    if status != "ok":
        return f"status {status if status is not None else 'missing'}"
    if row.get("incomplete"):
        return "adapter reported the run incomplete"
    if row.get("error"):
        return "error recorded"
    commands = row.get("commands")
    if not isinstance(commands, list):
        return "no command records"
    for command in commands:
        if not isinstance(command, dict):
            return "malformed command record"
        if command.get("timed_out"):
            return "command timed out"
        if command.get("ok") is not True:
            return f"command exit code {command.get('exit_code')} is not one the adapter declares as success"
    return None


def _completeness(
    corpus: EstateCorpus, rows: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], set[str], int, int]:
    """Incomplete and missing units, the entity ids they leave unscored, and
    the command count and non-zero exits the adapter accepted."""
    if not rows:
        return [{"unit": "all", "reason": MISSING_RUN}], {entity.id for entity in corpus.entities}, 0, 0
    gaps: dict[str, str] = {}
    commands = accepted_nonzero = 0
    for row in rows:
        unit = str(row.get("unit", "estate"))
        reason = incomplete_reason(row)
        if reason is not None:
            gaps.setdefault(unit, reason)
        for command in row.get("commands") or []:
            if isinstance(command, dict):
                commands += 1
                if command.get("ok") is True and command.get("exit_code") not in (0, None):
                    accepted_nonzero += 1
    seen = {str(row.get("unit", "estate")) for row in rows}
    kinds = {unit.partition(":")[0] for unit in seen if unit_bound(unit)}
    for entity in corpus.entities:
        if unit_bound(entity.unit) and entity.unit.partition(":")[0] in kinds and entity.unit not in seen:
            gaps.setdefault(entity.unit, MISSING_RUN)
    unscored = {entity.id for entity in corpus.entities if any(reaches(unit, entity) for unit in gaps)}
    listed = [{"unit": unit, "reason": reason} for unit, reason in sorted(gaps.items())]
    return listed, unscored, commands, accepted_nonzero


def _unattributed_in_scope(prediction: dict[str, Any], surfaces: frozenset[str]) -> bool:
    placed = placement(prediction)
    return not placed or bool(placed & surfaces)


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
    gaps, unscored, commands, accepted_nonzero = _completeness(corpus, rows)

    value_in_scope = Counts()
    value_all = Counts()
    by_surface: dict[str, Counts] = {surface: Counts() for surface in taxonomy.SURFACES}
    entity_rows: dict[str, dict[str, Any]] = {}
    # In-scope tallies per class: entities, detected or flagged, and unscored without a hit.
    in_scope_total: dict[str, int] = defaultdict(int)
    in_scope_hit: dict[str, int] = defaultdict(int)
    in_scope_unscored: dict[str, int] = defaultdict(int)
    detected_all = flagged_all = out_of_scope = 0
    shadow_expected = shadow_correct = 0

    for entity in corpus.entities:
        attributed = attribution.entity_predictions[entity.id]
        in_scope = entity.surface in surfaces
        if not in_scope:
            out_of_scope += len(attributed)
        facts = {str(p["fact"]) for p in attributed} - set(entity.tolerated)
        counts = match_values(facts, entity.expected_facts)
        entity_unscored = entity.id in unscored
        if entity_unscored:
            counts = Counts(tp=0, fp=counts.fp, fn=counts.fn + counts.tp)
        if in_scope:
            value_in_scope.add(counts)
        by_surface[entity.surface].add(counts)
        value_all.add(counts)
        positive = entity.klass == "positive"
        entity_detected = positive and counts.tp > 0
        entity_flagged = not positive and bool(facts)
        detected_all += entity_detected
        flagged_all += entity_flagged
        if in_scope:
            in_scope_total[entity.klass] += 1
            if entity_detected or entity_flagged:
                in_scope_hit[entity.klass] += 1
            elif entity_unscored:
                in_scope_unscored[entity.klass] += 1
        verdicts = [p.get("shadow") for p in attributed if p.get("shadow") is not None]
        if in_scope and entity_detected and verdicts:
            shadow_expected += 1
            wants_shadow = not entity.registered
            if all(v is wants_shadow for v in verdicts):
                shadow_correct += 1
        entity_rows[entity.id] = {
            "class": entity.klass,
            "surface": entity.surface,
            "detected": entity_detected,
            "flagged": entity_flagged,
            "unscored": entity_unscored,
            "tp": counts.tp,
            "fp": counts.fp,
            "fn": counts.fn,
        }

    unattributed_scoped = [p for p in attribution.unattributed if _unattributed_in_scope(p, surfaces)]
    out_of_scope += len(attribution.unattributed) - len(unattributed_scoped)
    value_in_scope.fp += len(unattributed_scoped)
    value_all.fp += len(attribution.unattributed)

    detected = in_scope_hit["positive"]
    flagged = in_scope_hit["control"] + in_scope_hit["nearmiss"]
    negatives_unscored = in_scope_unscored["control"] + in_scope_unscored["nearmiss"]
    entity_counts = Counts(tp=detected, fp=flagged, fn=in_scope_total["positive"] - detected)
    true_negatives = in_scope_total["control"] + in_scope_total["nearmiss"] - flagged - negatives_unscored
    positives_all = len(corpus.by_class("positive"))
    statuses: dict[str, int] = defaultdict(int)
    for row in rows:
        statuses[str(row.get("status", "missing"))] += 1
    seconds = sorted(float(row.get("seconds", 0.0)) for row in rows)

    return {
        "runs": dict(sorted(statuses.items())),
        "units": len(rows),
        "complete": not gaps,
        "incomplete_units": gaps,
        "commands": {"total": commands, "nonzero_exit_accepted": accepted_nonzero},
        "seconds": {
            "median": round(median(seconds), 2) if seconds else None,
            "max": round(seconds[-1], 2) if seconds else None,
            "total": round(sum(seconds), 2),
        },
        "entity_level": {
            **entity_counts.to_dict(),
            "tn": true_negatives,
            "positives": in_scope_total["positive"],
            "positives_detected": detected,
            "positives_unscored": in_scope_unscored["positive"],
            "controls": in_scope_total["control"],
            "controls_flagged": in_scope_hit["control"],
            "nearmiss": in_scope_total["nearmiss"],
            "nearmiss_flagged": in_scope_hit["nearmiss"],
            "negatives_unscored": negatives_unscored,
        },
        "estate_wide": {
            "positives": positives_all,
            "positives_detected": detected_all,
            "recall": round(detected_all / positives_all, _ROUND) if positives_all else None,
            "negatives": len(corpus.entities) - positives_all,
            "negatives_flagged": flagged_all,
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
        "predictions": {
            "total": len(predictions),
            "tolerated": attribution.tolerated,
            "attributed": sum(len(items) for items in attribution.entity_predictions.values()),
            "ambiguous": len(attribution.ambiguous),
            "unattributed": len(attribution.unattributed),
            "out_of_scope": out_of_scope,
        },
        "ambiguous": attribution.ambiguous[:50],
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
