"""Render ``metrics.json`` as Markdown.

``python -m tools.shadowbench.cases report --corpus corpus.json --metrics metrics.json --out REPORT.md``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.contract import SURFACES
from tools.shadowbench.cases.corpus import load_corpus

_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.0f}%"


def ci(pair: Any) -> str:
    if not pair or pair[0] is None:
        return ""
    return f" ({100 * pair[0]:.0f}–{100 * pair[1]:.0f})"


def secs(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


def errors(entry: dict[str, Any]) -> str:
    missing = entry.get("missing") or 0
    return f"{entry['errors']} ({missing} missing)" if missing else str(entry["errors"])


def p_value(entry: dict[str, Any]) -> str:
    """The McNemar p, or n/a when the tools share no case (no test was possible)."""
    p = entry.get("mcnemar_p")
    return "n/a" if p is None or entry.get("shared") == 0 else f"{p:.3f}"


def harness(manifest: dict[str, Any]) -> str:
    """The harness revision the run recorded, as a sentence to append.

    Manifests written before the runner recorded it, the committed 2026-10-11 run's among them,
    have no ``harness_commit`` key; their reports say what that means for the rows instead.
    """
    if "harness_commit" not in manifest:
        return (
            " The manifest predates the harness fields, so the code that produced these rows is not"
            " recorded: they come from earlier adapters, run under weaker isolation than the current"
            " runner's (tools ran as root, with the host's home directories in view), and the scoring"
            " rules were revised after the run, with its results in view. The benchmark README's"
            " Integration changes describe both."
        )
    commit = manifest["harness_commit"]
    if commit is None:
        return " The runner could not name the harness commit it ran from."
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        return " The manifest's harness commit is not a commit id, so the code the run came from is unknown."
    dirty = manifest.get("harness_dirty")
    if dirty is False:
        state = "with no uncommitted changes under `tools/`"
    elif dirty is True:
        state = "with uncommitted or untracked files under `tools/`, which that commit does not describe"
    else:
        state = "with an unknown working-tree state"
    return f" The runner, stage and adapters ran from harness commit `{commit}` {state}."


def withheld(metrics: dict[str, Any]) -> list[str]:
    """The paragraph naming the decoys adapters withheld from their tools; nothing when none was.

    Metrics written before the scorer knew of withheld decoys have no such counts and render none.
    """
    parts = []
    for name in _tool_order(metrics):
        tool = metrics["tools"][name]
        decoys = tool["in_scope"].get("decoys_withheld") or 0
        negatives = (tool["in_scope"].get("case") or {}).get("negatives_withheld") or 0
        if not decoys and not negatives:
            continue
        where = "; ".join(
            f"{place}, keys starting {', '.join(f'`{p}`' for p in prefixes)}"
            for place, prefixes in (tool.get("withheld_decoys") or {}).items()
        )
        cases = f" and {negatives} negative case{'s' * (negatives != 1)}" if negatives else ""
        parts.append(f"{name}, {decoys} decoy{'s' * (decoys != 1)}{cases} ({where})")
    if not parts:
        return []
    return [
        "Decoys whose records a tool's adapter never passes to it, as the adapter declares, are left out "
        "of that tool's specificity and agent false-alarm denominators unless the tool reports one anyway, "
        "and a negative case whose every decoy was withheld is left out of its case-level results and the "
        "paired comparison: " + "; ".join(parts) + ".",
        "",
    ]


def _tool_order(metrics: dict[str, Any]) -> list[str]:
    def key(name: str) -> tuple[float, str]:
        est = metrics["tools"][name]["estate"]["recall"]
        return (-(est or 0.0), name)

    return sorted(metrics["tools"], key=key)


def render(metrics: dict[str, Any], corpus_path: Path) -> str:
    corpus = load_corpus(corpus_path)
    lines: list[str] = ["# ShadowBench: nine-surface shadow AI agent discovery benchmark", ""]
    m = metrics.get("manifest", {})
    n_cases = len(corpus.cases)
    n_expected = sum(len(c.expected) for c in corpus.cases)
    n_decoys = sum(len(c.decoys) for c in corpus.cases)
    lines.append(
        f"Corpus: {n_cases} cases on {len({c.surface for c in corpus.cases})} surfaces carrying {n_expected} expected "  # noqa: E501
        f"entities and {n_decoys} decoys (SHA-256 `{metrics.get('corpus_sha256')}`, generator "
        f"`{metrics.get('generator_digest')}`). Run started {m.get('started')} and finished {m.get('finished')} on "  # noqa: E501
        f"{m.get('platform')} with {m.get('workers')} parallel workers; timings include contention."
        + harness(m)
    )
    lines.append("")
    lines.append(
        "Ground truth is generated from written rubrics with per-entity evidence (see the README). It is "
        "author-written and synthetic, not independent human review and not a sample of any real estate; the "
        "results describe how each tool behaves on these inputs, not field precision or recall."
    )
    lines.append("")
    unbound = metrics.get("rows_unbound") or []
    if unbound:
        whose = "any" if set(unbound) >= set(metrics["tools"]) else "the"
        names = "" if whose == "any" else " of " + ", ".join(f"`{name}`" for name in unbound)
        lines.append(
            f"The manifest records no SHA-256 of {whose} results file{names}, so those rows are bound to the "
            "run only by their per-status row counts, which an edited or swapped file can keep."
        )
        lines.append("")
    # every forced override is listed, the corpus digest mismatch among them
    forced = metrics.get("forced") or []
    if forced:
        lines.append(
            "**Warning:** scored with `--force` over these refusals; case ids are positional, so the numbers "
            "below may compare tools with the wrong truth or score results no run of this corpus produced:"
        )
        lines.append("")
        for problem in forced:
            lines.append(f"- {problem}")
        lines.append("")
    skipped = {
        k: v.get("skipped")
        for k, v in metrics.get("tool_runs", {}).items()
        if isinstance(v, dict) and v.get("skipped")
    }
    if skipped:
        lines.append("Tools configured but not run:")
        lines.append("")
        for name, reason in sorted(skipped.items()):
            scored = " (a results file for it was scored with `--force`)" if name in metrics["tools"] else ""
            lines.append(f"- `{name}`: {reason}{scored}")
        lines.append("")
    lines += ["## Headline", ""]
    lines.append(
        "| Tool | Version | Surfaces | Estate recall | In-scope entity P / R / F1 | Specificity on decoys | "
        "Agent recall | Agent false alarms | Case-level balanced accuracy | Errors | Incomplete | Seconds median / p90 |"  # noqa: E501
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name in _tool_order(metrics):
        t = metrics["tools"][name]
        i = t["in_scope"]
        lines.append(
            f"| {name} | {t.get('version') or ''} | {t['coverage']}: {', '.join(t['surfaces_supported'])} | "
            f"{pct(t['estate']['recall'])} ({t['estate']['tp']}/{t['estate']['expected']}) | "
            f"{pct(i['precision'])} / {pct(i['recall'])} / {pct(i['f1'])}{ci(i.get('f1_ci'))} | "
            f"{pct(i['specificity'])} | {pct(i['agent_recall'])} ({i['agent_tp']}/{i['agent_expected']}) | "
            f"{pct(i['agent_false_alarm_rate'])} ({i['agent_false_alarms']}/{i['agent_false_alarm_universe']}) | "  # noqa: E501
            f"{pct(i['case']['balanced_accuracy'])} | {errors(i)} | {i['incomplete']} | "
            f"{secs(i['seconds_median'])} / {secs(i['seconds_p90'])} |"
        )
    lines.append("")
    lines.append(
        "Estate recall counts every expected entity in the corpus, charging a tool for the surfaces it does not "  # noqa: E501
        "cover. In-scope metrics count only the surfaces and modalities a tool ran on. Specificity is measured on "  # noqa: E501
        "decoy entities (records labeled none). Agent recall is the share of expected agents a tool reported as "  # noqa: E501
        "agents; agent false alarms are plain-AI entities and decoys it called agents. F1 intervals are 2,000-sample "  # noqa: E501
        "case bootstraps. At case level a positive case is found when the tool reports at least one "
        "expected entity, and a negative case is a false alarm when it reports any false positive or, on "
        "the code surface, anything outside the fact taxonomy. An "
        "error, or a case with no result row (counted as missing), is never a correct outcome: its "
        "expected entities are missed, its decoys are not true negatives, and the case counts as missed "
        "or as a false alarm. A scan the tool marked incomplete keeps what it reported but never earns a "
        "true negative: its unflagged decoys are not true negatives, a negative case it scanned "
        "incompletely counts as a false alarm, and only the entities it called agents enter the agent "
        "false-alarm denominator."
    )
    lines.append("")
    lines += withheld(metrics)
    lines += ["## By surface", ""]
    for surface in SURFACES:
        info = metrics["surfaces"].get(surface)
        if not info or not info["cases"]:
            continue
        lines.append(
            f"### {surface} ({info['cases']} cases, {info['positives']} positive; {info['expected']} expected "  # noqa: E501
            f"entities, {info['decoys']} decoys; modalities {', '.join(info['modalities'])})"
        )
        lines.append("")
        lines.append(
            "| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | "  # noqa: E501
            "Case recall / specificity | Errors | Incomplete | Seconds median |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        any_row = False
        for name in _tool_order(metrics):
            s = metrics["tools"][name]["by_surface"].get(surface)
            if not s:
                continue
            any_row = True
            c = s["case"]
            lines.append(
                f"| {name} | {', '.join(s['modalities'])} | {pct(s['precision'])} / {pct(s['recall'])} / "
                f"{pct(s['f1'])}{ci(s.get('f1_ci'))} | {s['tp']} / {s['fp']} / {s['fn']} / {s['tn']} | "
                f"{pct(s['specificity'])} | {pct(s['agent_recall'])} | {pct(s['agent_false_alarm_rate'])} | "
                f"{pct(c['recall'])} / {pct(c['specificity'])} | {errors(s)} | {s['incomplete']} | "
                f"{secs(s['seconds_median'])} |"
            )
        if not any_row:
            lines.append("| (no tool ran on this surface) | | | | | | | | | | |")
        lines.append("")
        if surface == "code" and any_row:
            code = {
                name: metrics["tools"][name]["by_surface"][surface]
                for name in _tool_order(metrics)
                if metrics["tools"][name]["by_surface"].get(surface)
            }
            counts = [f"{name} {s.get('out_of_taxonomy', 0)}" for name, s in code.items()]
            alarms = [f"{name} {s['case'].get('out_of_taxonomy_alarms', 0)}" for name, s in code.items()]
            lines.append(
                "Reports outside the code fact taxonomy (for example file paths an adapter could not map to "
                "a fact, whether it passed them on or dropped and counted them) are neither true nor false "
                "positives, for every tool: "
                + ", ".join(counts)
                + ". At case level such a report earns a positive case nothing and is a false alarm on a "
                "negative one, which happened on " + ", ".join(alarms) + "."
            )
            lines.append("")
        # modality breakdown
        mods = sorted(
            {
                mod
                for name in metrics["tools"]
                for mod in (metrics["tools"][name]["by_surface"].get(surface) or {}).get("modalities", {})
            }
        )
        if len(mods) > 1:
            lines.append("| Tool | " + " | ".join(f"{mod} P / R / F1" for mod in mods) + " |")
            lines.append("|---|" + "---|" * len(mods))
            for name in _tool_order(metrics):
                s = metrics["tools"][name]["by_surface"].get(surface)
                if not s:
                    continue
                cells = []
                for mod in mods:
                    mm = s["modalities"].get(mod)
                    cells.append(
                        f"{pct(mm['precision'])} / {pct(mm['recall'])} / {pct(mm['f1'])}" if mm else "not run"
                    )
                lines.append(f"| {name} | " + " | ".join(cells) + " |")
            lines.append("")
    lines += ["## Paired comparison", ""]
    lines.append(
        "Exact McNemar test on case-level correctness against the reference tool, over cases both tools ran "
        "(n/a when they share none)."
    )
    lines.append("")
    lines.append(
        "| Tool | Reference | Shared cases | Tool right, reference wrong | Reference right, tool wrong | p |"
    )
    lines.append("|---|---|---|---|---|---|")
    for name in _tool_order(metrics):
        v = metrics["tools"][name].get("vs_reference")
        if v:
            lines.append(
                f"| {name} | {v['reference']} | {v.get('shared', '')} | {v['tool_only_correct']} | "
                f"{v['reference_only_correct']} | {p_value(v)} |"
            )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--metrics", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    args.out.write_text(render(metrics, args.corpus), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
