"""Render estate metrics.json as Markdown."""

from __future__ import annotations

from typing import Any

from tools.shadowbench.estate import score, taxonomy
from tools.shadowbench.estate.corpus import EstateCorpus


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{round(value * 100)}%"


def _prf(counts: dict[str, Any]) -> str:
    return f"{_pct(counts.get('precision'))} / {_pct(counts.get('recall'))} / {_pct(counts.get('f1'))}"


def _sorted_tools(metrics: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    def key(item: tuple[str, dict[str, Any]]) -> tuple[float, float]:
        data = item[1]
        in_scope = data["value_level"]["in_scope"].get("f1") or 0.0
        entity_f1 = data["entity_level"].get("f1") or 0.0
        return (-in_scope, -entity_f1)

    return sorted(metrics["tools"].items(), key=key)


def render(metrics: dict[str, Any], corpus: EstateCorpus, *, title: str) -> str:
    lines: list[str] = [f"# {title}", ""]
    c = metrics["corpus"]
    lines.append(
        f"Corpus: {c['entities']} labeled entities across the nine surfaces "
        f"({c['positive']} positive carrying {c['expected_facts']} expected facts, "
        f"{c['control']} control, {c['nearmiss']} near-miss; {c['registered']} positives are "
        f"registered in the supplied agent registry)."
    )
    run = metrics.get("run", {})
    lines.append(
        f"Run started {run.get('started')} and finished {run.get('finished')}; "
        "runs are parallel, so timings include contention and are indicative only."
    )
    lines.append("")
    lines.append(
        "Ground truth is author-written labeling with evidence pointers, frozen before any "
        "tool ran. It is not independent human review; the same maintainer wrote ShadowScan, "
        "the harness and the labels. See the benchmark README for the protocol and its limits."
    )
    lines.append("")
    skipped = run.get("tools_skipped", {})
    if skipped:
        lines.append("Tools skipped in this run:")
        lines.append("")
        for tool, reason in sorted(skipped.items()):
            lines.append(f"- `{tool}`: {reason}")
        lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append(
        "| Tool | Surfaces declared | Runs | Positives detected (in scope) | "
        "Entity TP/FP/TN/FN (in scope) | Entity P / R / F1 (in scope) | In-scope value P / R / F1 | "
        "Positives detected (estate-wide) | Estate-wide value recall | Seconds median / max |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for _tool_id, data in _sorted_tools(metrics):
        entity = data["entity_level"]
        estate = data["estate_wide"]
        seconds = data["seconds"]
        lines.append(
            f"| {data['name']} ({data['version']}) "
            f"| {', '.join(data['surfaces'])} "
            f"| {_runs_cell(data)} "
            f"| {entity['positives_detected']}/{entity['positives']} "
            f"| {entity['tp']}/{entity['fp']}/{entity['tn']}/{entity['fn']} "
            f"| {_prf(entity)} "
            f"| {_prf(data['value_level']['in_scope'])} "
            f"| {estate['positives_detected']}/{estate['positives']} "
            f"| {_pct(data['value_level']['all'].get('recall'))} "
            f"| {seconds['median']} / {seconds['max']} |"
        )
    lines.append("")
    lines.append(
        "In-scope metrics count only the entities and expected facts on the surfaces a tool "
        "declares: entity TP/FP/TN/FN are positives detected, negatives flagged, negatives left "
        "clean and positives missed among those entities. A negative counts as a true negative only "
        "when a complete run of the tool reached it. The estate-wide columns charge every tool for "
        "every positive and every expected fact on all nine surfaces. A tool marked incomplete had "
        "at least one run that did not complete; see Run status."
    )
    lines.append("")

    tools = _sorted_tools(metrics)
    lines.append("## Run status")
    lines.append("")
    lines.append(
        "| Tool | Units run | Statuses | Incomplete or missing units | Commands | "
        "Non-zero exits the adapter accepts | Unscored in-scope entities | "
        "In-scope entities no complete run reached |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for _tool_id, data in tools:
        statuses = ", ".join(f"{count} {status}" for status, count in data["runs"].items()) or "none"
        lines.append(
            f"| {data['name']} | {data['units']} | {statuses} | {_gaps_cell(data)} "
            f"| {data['commands']['total']} | {data['commands']['nonzero_exit_accepted']} "
            f"| {len(_unscored_in_scope(data))} | {len(_not_reached_in_scope(data))} |"
        )
    lines.append("")
    lines.append(
        "A run is incomplete when its status is not ok, the adapter reported it incomplete, it "
        "recorded an error, it ran no command, a command timed out or exited with a code the "
        "adapter does not declare as success, or every one of its commands exited non-zero and it "
        "produced no output. A code or home unit that labels an entity on the tool's declared "
        "surfaces is missing when the tool has no run for it and no whole-estate run. Every entity "
        "an incomplete or missing run reaches is unscored: its positives count as missed and its "
        "negatives earn no true negative, so a failed run never reads as a clean result. An entity "
        "that no complete run reaches, such as an estate export outside every home tree a per-home "
        "tool scans, is not reached: its positives count as missed and its negatives earn no true "
        "negative either. Other non-zero exits an adapter declares as success are counted here but "
        "not treated as failures. runs.json records exit codes but no stderr, so whether such an "
        'exit meant "nothing found" or a failure cannot be checked from the published results; that '
        "is why a run whose commands all exited non-zero without output counts as incomplete."
    )
    lines.append("")

    lines.append("## Attribution")
    lines.append("")
    lines.append(
        "| Tool | Predictions | Tolerated | Attributed | Matched several entities | Ambiguous | "
        "Unattributed | Outside declared surfaces |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for _tool_id, data in tools:
        counts = data["predictions"]
        lines.append(
            f"| {data['name']} | {counts['total']} | {counts['tolerated']} | {counts['attributed']} "
            f"| {counts['multi_match']} | {counts['ambiguous']} | {counts['unattributed']} "
            f"| {counts['out_of_scope']} |"
        )
    lines.append("")
    lines.append(
        "A prediction is attributed only to an entity on its own surface that its run can reach "
        "(for a per-repository or per-home run, the entities with artifacts in that repository or "
        "home tree). When the anchors of several positives appear in a prediction, one that expects "
        "the predicted fact wins, then one whose expected or tolerated facts share its category. "
        "When a control or near-miss is among them, that preference does not apply, so a flag on a "
        "negative is never handed to a positive. What is still tied goes to the longest anchor, "
        "then the first entity id in sort order. Every prediction matching several entities is "
        "listed under its tool below with the rule that chose its owner; it is ambiguous when the "
        "anchor length or the id chose. A per-repository or per-home prediction that names no "
        "anchor goes to the one entity of that repository or home that expects its fact, if there "
        "is exactly one. Tolerated counts predictions dropped by a corpus-level tolerated pair. "
        "Unattributed predictions are false positives. Predictions outside the declared surfaces "
        "count in the estate-wide numbers only."
    )
    lines.append("")
    harness = _harness_sentence(tools)
    if harness:
        lines.append(harness)
        lines.append("")

    lines.append("## Value-level F1 by surface")
    lines.append("")
    surfaces = list(taxonomy.SURFACES)
    expected = metrics["corpus"]["expected_by_surface"]
    header = " | ".join(f"{s} (n={expected.get(s, 0)})" for s in surfaces)
    lines.append(f"| Tool | {header} |")
    lines.append("|---" * (len(surfaces) + 1) + "|")
    for _tool_id, data in _sorted_tools(metrics):
        cells: list[str] = []
        for surface in surfaces:
            counts = data["value_level"]["by_surface"][surface]
            declared = surface in data["surfaces"]
            if not declared and counts["tp"] == 0 and counts["fp"] == 0:
                cells.append(f"out of scope (0/0/{counts['fn']})")
            else:
                cells.append(f"{_pct(counts.get('f1'))} ({counts['tp']}/{counts['fp']}/{counts['fn']})")
        lines.append(f"| {data['name']} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Cells read F1 (true positives / false positives / false negatives).")
    lines.append("")

    lines.append("## Control and near-miss entities")
    lines.append("")
    lines.append("| Entity | Surface | Class | " + " | ".join(d["name"] for _, d in tools) + " |")
    lines.append("|---" * (len(tools) + 3) + "|")
    for entity in corpus.entities:
        if entity.klass == "positive":
            continue
        cells = []
        for _tool_id, data in tools:
            row = data["per_entity"].get(entity.id, {})
            if entity.surface not in data["surfaces"]:
                cells.append("out of scope")
            elif row.get("flagged"):
                cells.append("flagged")
            elif row.get("unscored", True):
                cells.append("unscored")
            else:
                cells.append("clean" if row.get("reached", False) else "not reached")
        lines.append(f"| {entity.id} | {entity.surface} | {entity.klass} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append(
        "An unscored negative was reached by an incomplete or missing run, and no complete run of the "
        "tool reached a negative marked not reached; neither is a true negative."
    )
    lines.append("")

    lines.append("## Registry reconciliation (shadow layer)")
    lines.append("")
    lines.append("| Tool | Detected positives with a verdict | Correct verdicts |")
    lines.append("|---|---|---|")
    for _tool_id, data in tools:
        layer = data["shadow_layer"]
        if layer["scored"] == 0:
            lines.append(f"| {data['name']} | no registry reconciliation | n/a |")
        else:
            lines.append(f"| {data['name']} | {layer['scored']} | {layer['correct']} |")
    lines.append("")
    lines.append(
        "A verdict is correct when every finding attributed to the entity carries the "
        "expected reconciliation: registered entities read registered, unregistered "
        "positives read shadow."
    )
    lines.append("")

    lines.append("## Misses and extra findings by tool")
    lines.append("")
    for _tool_id, data in tools:
        lines.append(f"### {data['name']}")
        lines.append("")
        missed = [
            entity_id
            for entity_id, row in data["per_entity"].items()
            if row["class"] == "positive" and not row["detected"] and row["surface"] in data["surfaces"]
        ]
        lines.append(f"Missed in-scope positives: {', '.join(missed) if missed else 'none'}")
        lines.append("")
        unscored = _unscored_in_scope(data)
        if unscored:
            lines.append(
                "Unscored in-scope entities (reached by an incomplete or missing run; positives count "
                f"as missed, negatives earn no true negative): {', '.join(unscored)}"
            )
            lines.append("")
        not_reached = _not_reached_in_scope(data)
        if not_reached:
            lines.append(
                "In-scope entities no complete run reached (positives count as missed, negatives earn "
                f"no true negative): {', '.join(not_reached)}"
            )
            lines.append("")
        multi = data.get("multi_match", [])
        if multi:
            lines.append(
                f"Predictions matching several entities: {data['predictions']['multi_match']}, of which "
                f"{data['predictions']['ambiguous']} ambiguous (owner chosen by anchor length or entity "
                "id, not by the entities' labels):"
            )
            lines.append("")
            for item in multi[:15]:
                lines.append(
                    f"- `{item['fact']}` → {item['entity']} by {item['rule']} "
                    f"(candidates: {', '.join(item['candidates'])}) — {item['text']}"
                )
            if data["predictions"]["multi_match"] > 15:
                lines.append(f"- … and {data['predictions']['multi_match'] - 15} more")
            lines.append("")
        extras = data.get("unattributed", [])
        if extras:
            lines.append("Predictions attributed to no entity (charged as false positives):")
            lines.append("")
            for item in extras[:15]:
                target = item.get(score.SCAN_TARGET)
                note = f" (scan target `{target}` maps to no estate host)" if target is not None else ""
                lines.append(f"- `{item['fact']}` — {item['text']}{note}")
            if len(extras) > 15:
                lines.append(f"- … and {len(extras) - 15} more")
            lines.append("")
    return "\n".join(lines) + "\n"


def _harness_sentence(tools: list[tuple[str, dict[str, Any]]]) -> str:
    """The harness-attribution counts, or "" when no tool's runs record scan targets."""
    parts: list[str] = []
    for _tool_id, data in tools:
        counts = data["predictions"]
        if "harness_attributed" not in counts:
            continue
        part = f"{data['name']} {counts['harness_attributed']}"
        if counts.get("unknown_scan_target"):
            part += (
                f" (plus {counts['unknown_scan_target']} whose scan target maps to no estate host, "
                "counted as false positives)"
            )
        parts.append(part)
    if not parts:
        return ""
    return (
        f"Harness-attributed predictions: {'; '.join(parts)}. For these the harness mapped a scanned "
        "loopback port to the estate host it stands in for (`artifacts/services/services.json`); the "
        "tool itself named only the loopback port it scanned."
    )


def _unscored_in_scope(data: dict[str, Any]) -> list[str]:
    return [
        entity_id
        for entity_id, row in data["per_entity"].items()
        if row.get("unscored", True) and row["surface"] in data["surfaces"]
    ]


def _not_reached_in_scope(data: dict[str, Any]) -> list[str]:
    return [
        entity_id
        for entity_id, row in data["per_entity"].items()
        if not row.get("unscored", True)
        and not row.get("reached", False)
        and row["surface"] in data["surfaces"]
    ]


def _gaps_cell(data: dict[str, Any]) -> str:
    """Incomplete or missing units, grouped by reason."""
    by_reason: dict[str, list[str]] = {}
    for gap in data["incomplete_units"]:
        by_reason.setdefault(gap["reason"], []).append(gap["unit"])
    return "; ".join(f"{reason}: {', '.join(units)}" for reason, units in by_reason.items()) or "none"


def _runs_cell(data: dict[str, Any]) -> str:
    """Per-tool run status counts, marked when any run is incomplete or missing."""
    parts = [f"{count} {status}" for status, count in data["runs"].items()]
    missing = sum(1 for gap in data["incomplete_units"] if gap["reason"] == score.MISSING_RUN)
    if missing:
        parts.append(f"{missing} missing")
    text = ", ".join(parts) or "none"
    return text if data["complete"] else f"**incomplete** ({text})"
