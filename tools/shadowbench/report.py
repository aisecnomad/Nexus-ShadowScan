"""Render estate metrics.json as Markdown."""

from __future__ import annotations

from typing import Any

from tools.shadowbench import taxonomy
from tools.shadowbench.corpus import EstateCorpus


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
        "| Tool | Surfaces declared | Positives detected | Entity TP/FP/TN/FN | "
        "Entity P / R / F1 | In-scope value P / R / F1 | Estate-wide value recall | "
        "Seconds median / max | Incomplete units |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for _tool_id, data in _sorted_tools(metrics):
        entity = data["entity_level"]
        seconds = data["seconds"]
        lines.append(
            f"| {data['name']} ({data['version']}) "
            f"| {', '.join(data['surfaces'])} "
            f"| {entity['positives_detected']}/{entity['positives']} "
            f"| {entity['tp']}/{entity['fp']}/{entity['tn']}/{entity['fn']} "
            f"| {_prf(entity)} "
            f"| {_prf(data['value_level']['in_scope'])} "
            f"| {_pct(data['value_level']['all'].get('recall'))} "
            f"| {seconds['median']} / {seconds['max']} "
            f"| {len(data['incomplete_units'])} |"
        )
    lines.append("")
    lines.append(
        "In-scope metrics count only the surfaces a tool declares; the estate-wide recall "
        "charges every tool for every expected fact on all nine surfaces. Entity TP/FP/TN/FN "
        "count positives detected, negatives flagged, negatives left clean and positives "
        "missed, on the tool's declared surfaces."
    )
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
    tools = _sorted_tools(metrics)
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
            else:
                cells.append("flagged" if row.get("flagged") else "clean")
        lines.append(f"| {entity.id} | {entity.surface} | {entity.klass} | " + " | ".join(cells) + " |")
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
        extras = data.get("unattributed", [])
        if extras:
            lines.append("Predictions attributed to no entity (charged as false positives):")
            lines.append("")
            for item in extras[:15]:
                lines.append(f"- `{item['fact']}` — {item['text']}")
            if len(extras) > 15:
                lines.append(f"- … and {len(extras) - 15} more")
            lines.append("")
    return "\n".join(lines) + "\n"
