"""Render ``metrics.json`` as Markdown.

``python -m tools.shadowbench.cases report --corpus corpus.json --metrics metrics.json --out REPORT.md``
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.contract import SURFACES
from tools.shadowbench.cases.corpus import load_corpus


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.0f}%"


def ci(pair: Any) -> str:
    if not pair or pair[0] is None:
        return ""
    return f" ({100 * pair[0]:.0f}–{100 * pair[1]:.0f})"


def secs(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


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
    )
    lines.append("")
    lines.append(
        "Ground truth is generated from written rubrics with per-entity evidence (see the README). It is "
        "author-written and synthetic, not independent human review and not a sample of any real estate; the "
        "results describe how each tool behaves on these inputs, not field precision or recall."
    )
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
            lines.append(f"- `{name}`: {reason}")
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
            f"{pct(i['case']['balanced_accuracy'])} | {i['errors']} | {i['incomplete']} | "
            f"{secs(i['seconds_median'])} / {secs(i['seconds_p90'])} |"
        )
    lines.append("")
    lines.append(
        "Estate recall counts every expected entity in the corpus, charging a tool for the surfaces it does not "  # noqa: E501
        "cover. In-scope metrics count only the surfaces and modalities a tool ran on. Specificity is measured on "  # noqa: E501
        "decoy entities (records labeled none). Agent recall is the share of expected agents a tool reported as "  # noqa: E501
        "agents; agent false alarms are plain-AI entities and decoys it called agents. F1 intervals are 2,000-sample "  # noqa: E501
        "case bootstraps."
    )
    lines.append("")
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
                f"{pct(c['recall'])} / {pct(c['specificity'])} | {s['errors']} | {s['incomplete']} | "
                f"{secs(s['seconds_median'])} |"
            )
        if not any_row:
            lines.append("| (no tool ran on this surface) | | | | | | | | | | |")
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
        "Exact McNemar test on case-level correctness against the reference tool, over cases both tools ran."
    )
    lines.append("")
    lines.append("| Tool | Reference | Tool right, reference wrong | Reference right, tool wrong | p |")
    lines.append("|---|---|---|---|---|")
    for name in _tool_order(metrics):
        v = metrics["tools"][name].get("vs_reference")
        if v:
            lines.append(
                f"| {name} | {v['reference']} | {v['tool_only_correct']} | {v['reference_only_correct']} | {v['mcnemar_p']:.3f} |"  # noqa: E501
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
