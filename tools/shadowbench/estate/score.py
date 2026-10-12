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
   (case-insensitive substring), when all of them are positives, an entity
   that expects the predicted fact (exactly, or by category for a
   `generic` value) beats one whose expected or tolerated facts share its
   category, which beats the rest. When a control or near-miss is among
   them, that preference does not apply, so a flag on a negative is never
   handed to a positive whose anchor merely co-occurs. Whatever is still
   tied goes to the longest matching anchor, then the entity id. Every
   prediction whose anchors match more than one candidate is recorded with
   the candidates and the rule that chose its owner, and it is counted as
   ambiguous when the anchor length or the id chose.
4. When no candidate's anchor matches and the run is unit-bound, the
   prediction falls back to the one candidate labeled with the run's own
   unit that expects the fact: inventory tools echo client names, not the
   corpus's anchors. Estate-wide entities take no fallback. With no such
   candidate, or several, the prediction stays unattributed.

An attributed prediction takes its entity's surface, so it is in scope
exactly when the tool declares that surface; an unattributed prediction is
in scope when its own placement touches a declared surface (or cannot be
placed at all). Predictions outside the declared surfaces count in the
estate-wide numbers only and are reported as out of scope, never dropped.

Completeness: a run row is incomplete when its status is not `ok`, the
adapter flagged it incomplete, it recorded an error, it ran no command, any
of its commands timed out or exited with a code the adapter did not declare
as success (the runner records that as the command's `ok`), or every one of
its commands exited non-zero and it produced no output: the adapter
accepted those exits, but "nothing found" cannot then be told from a
failure. A code or home unit that labels an entity on the tool's declared
surfaces is missing when the tool has no row for it and no whole-estate
row, and a tool with no rows at all is missing everywhere. Every entity an
incomplete or missing run reaches is *unscored* for the tool: its expected
facts count as missed, a positive is not detected, and a negative earns no
true negative (a flag on it is still a false positive). An entity that no
complete run reaches is *not reached*: a positive there is missed and a
negative earns no true negative. An incomplete run never reads as a clean
negative. Other non-zero exits an adapter declares as success are counted
and reported, not failed.

Scoring then uses the code-surface benchmark's value matching, except that
a surplus generic earns no second true positive here (the code-surface
scorer credits one):

- value level: exact facts, with `<category>:generic` consuming one expected
  fact of its category (a surplus generic on an expected category that is
  already matched is neither charged nor credited); tolerated facts are
  dropped before scoring; facts a tool reports outside the taxonomy never
  reach the scorer (adapters drop them). Unattributed predictions are false
  positives.
- entity level, in scope: only entities on the tool's declared surfaces. A
  positive is detected when an attributed prediction matches an expected
  fact; a control or near-miss is flagged by any attributed prediction.
  Unflagged negatives that a complete run reached and no incomplete or
  missing run reached are true negatives.
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
NO_OUTPUT = "every command exited non-zero and the run produced no output"

# Rules that pick the owner of a prediction whose anchors match several entities.
RULE_FACT = "expects the fact"
RULE_CATEGORY = "shares the fact's category"
RULE_ANCHOR = "longest anchor"
RULE_ID = "entity id"
#: Rules that choose by how the anchors read rather than by the entities' labels.
AMBIGUOUS_RULES = frozenset({RULE_ANCHOR, RULE_ID})


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
    #: Predictions whose anchors matched several candidates, with the rule that chose.
    multi_match: list[dict[str, Any]] = field(default_factory=list)
    tolerated: int = 0

    @property
    def ambiguous(self) -> list[dict[str, Any]]:
        """Multiple matches whose owner the anchors chose, not the entities' labels."""
        return [item for item in self.multi_match if item["rule"] in AMBIGUOUS_RULES]


def choose_owner(matched: list[tuple[Entity, int]], fact: str) -> tuple[Entity, str]:
    """The owner among anchor-matching (entity, longest anchor) pairs, and the rule that chose it.

    The preference for an entity that expects the fact, or its category, applies
    only among positives: a control or near-miss has no expected facts, so the
    preference would hand every flag on it to a positive whose anchor co-occurs.
    """
    pool = matched
    if all(entity.klass == "positive" for entity, _ in matched):
        best = min(_preference(entity, fact) for entity, _ in matched)
        pool = [(entity, length) for entity, length in matched if _preference(entity, fact) == best]
        if len(pool) == 1 and best < 2:
            return pool[0][0], RULE_FACT if best == 0 else RULE_CATEGORY
    longest = max(length for _, length in pool)
    top = sorted((entity for entity, length in pool if length == longest), key=lambda entity: entity.id)
    return top[0], RULE_ANCHOR if len(top) == 1 else RULE_ID


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
        matched: list[tuple[Entity, int]] = []
        for entity in reachable:
            lengths = [len(anchor) for anchor in entity.anchors if anchor in text]
            if lengths:
                matched.append((entity, max(lengths)))
        owner: Entity | None = None
        if matched:
            owner, rule = choose_owner(matched, fact)
            if len(matched) > 1:
                result.multi_match.append(
                    {
                        "fact": fact,
                        "text": str(prediction.get("text", ""))[:160],
                        "entity": owner.id,
                        "rule": rule,
                        "candidates": sorted(entity.id for entity, _ in matched),
                    }
                )
        elif unit_bound(unit):
            # Only the run's own unit: an estate-wide entity reached through the unit's
            # tree (an MCP server in several homes) must be named by its anchor.
            candidates = [entity for entity in reachable if entity.unit == unit and _expects(entity, fact)]
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
    if not commands:
        return "no commands run"
    for command in commands:
        if not isinstance(command, dict):
            return "malformed command record"
        if command.get("timed_out"):
            return "command timed out"
        if command.get("ok") is not True:
            return f"command exit code {command.get('exit_code')} is not one the adapter declares as success"
    if all(command.get("exit_code") != 0 for command in commands) and not (
        row.get("predictions") or row.get("raw_count")
    ):
        return NO_OUTPUT
    return None


@dataclass
class Completeness:
    """Incomplete and missing units, the entity ids they leave unscored, the
    entity ids some complete run reaches, and the command tallies."""

    gaps: list[dict[str, str]]
    unscored: set[str]
    reached: set[str]
    commands: int = 0
    accepted_nonzero: int = 0


def _completeness(corpus: EstateCorpus, surfaces: frozenset[str], rows: list[dict[str, Any]]) -> Completeness:
    if not rows:
        everything = {entity.id for entity in corpus.entities}
        return Completeness([{"unit": "all", "reason": MISSING_RUN}], everything, set())
    gaps: dict[str, str] = {}
    complete_units: set[str] = set()
    result = Completeness([], set(), set())
    for row in rows:
        unit = str(row.get("unit", "estate"))
        reason = incomplete_reason(row)
        if reason is None:
            complete_units.add(unit)
        else:
            gaps.setdefault(unit, reason)
        for command in row.get("commands") or []:
            if isinstance(command, dict):
                result.commands += 1
                if command.get("ok") is True and command.get("exit_code") not in (0, None):
                    result.accepted_nonzero += 1
    seen = {str(row.get("unit", "estate")) for row in rows}
    if all(unit_bound(unit) for unit in seen):
        for entity in corpus.entities:
            if entity.surface in surfaces and unit_bound(entity.unit) and entity.unit not in seen:
                gaps.setdefault(entity.unit, MISSING_RUN)
    result.gaps = [{"unit": unit, "reason": reason} for unit, reason in sorted(gaps.items())]
    for entity in corpus.entities:
        if any(reaches(unit, entity) for unit in gaps):
            result.unscored.add(entity.id)
        if any(reaches(unit, entity) for unit in complete_units - set(gaps)):
            result.reached.add(entity.id)
    return result


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
    completeness = _completeness(corpus, surfaces, rows)

    value_in_scope = Counts()
    value_all = Counts()
    by_surface: dict[str, Counts] = {surface: Counts() for surface in taxonomy.SURFACES}
    entity_rows: dict[str, dict[str, Any]] = {}
    # In-scope tallies per class: entities, detected or flagged, and, without a hit,
    # unscored or not reached by any complete run.
    in_scope_total: dict[str, int] = defaultdict(int)
    in_scope_hit: dict[str, int] = defaultdict(int)
    in_scope_unscored: dict[str, int] = defaultdict(int)
    in_scope_not_reached: dict[str, int] = defaultdict(int)
    detected_all = flagged_all = out_of_scope = 0
    shadow_expected = shadow_correct = 0

    for entity in corpus.entities:
        attributed = attribution.entity_predictions[entity.id]
        in_scope = entity.surface in surfaces
        if not in_scope:
            out_of_scope += len(attributed)
        facts = {str(p["fact"]) for p in attributed} - set(entity.tolerated)
        counts = match_values(facts, entity.expected_facts)
        entity_unscored = entity.id in completeness.unscored
        entity_reached = entity.id in completeness.reached
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
            elif not entity_reached:
                in_scope_not_reached[entity.klass] += 1
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
            "reached": entity_reached,
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
    negatives_not_reached = in_scope_not_reached["control"] + in_scope_not_reached["nearmiss"]
    entity_counts = Counts(tp=detected, fp=flagged, fn=in_scope_total["positive"] - detected)
    true_negatives = (
        in_scope_total["control"]
        + in_scope_total["nearmiss"]
        - flagged
        - negatives_unscored
        - negatives_not_reached
    )
    positives_all = len(corpus.by_class("positive"))
    statuses: dict[str, int] = defaultdict(int)
    for row in rows:
        statuses[str(row.get("status", "missing"))] += 1
    seconds = sorted(float(row.get("seconds", 0.0)) for row in rows)

    return {
        "runs": dict(sorted(statuses.items())),
        "units": len(rows),
        "complete": not completeness.gaps,
        "incomplete_units": completeness.gaps,
        "commands": {"total": completeness.commands, "nonzero_exit_accepted": completeness.accepted_nonzero},
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
            "positives_not_reached": in_scope_not_reached["positive"],
            "controls": in_scope_total["control"],
            "controls_flagged": in_scope_hit["control"],
            "nearmiss": in_scope_total["nearmiss"],
            "nearmiss_flagged": in_scope_hit["nearmiss"],
            "negatives_unscored": negatives_unscored,
            "negatives_not_reached": negatives_not_reached,
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
            "multi_match": len(attribution.multi_match),
            "ambiguous": len(attribution.ambiguous),
            "unattributed": len(attribution.unattributed),
            "out_of_scope": out_of_scope,
        },
        "multi_match": attribution.multi_match[:50],
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
