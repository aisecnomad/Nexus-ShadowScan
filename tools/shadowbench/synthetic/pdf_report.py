"""Render a ShadowBench run as a PDF: summary, ranking and grades, headline and per-surface metrics, method.

``python -m tools.shadowbench.synthetic pdf --corpus corpus.json --metrics metrics.json --grades grades.json
--out ShadowBench.pdf``

The grades file is a judgement over the measured numbers (``rubric``, ``caveat``,
``tools`` with ``rank``, ``in_scope``, ``program`` and ``rationale``, ``not_graded``);
the metrics are what the scorer computed. The PDF names the corpus hash, the
generator digest and every tool version so it can be checked against the run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.shadowbench.synthetic.contract import SURFACES
from tools.shadowbench.synthetic.corpus import load_corpus
from tools.shadowbench.synthetic.report import ci, pct, secs

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def _fonts() -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular, bold = FONT_DIR / "DejaVuSans.ttf", FONT_DIR / "DejaVuSans-Bold.ttf"
    if regular.exists() and bold.exists():
        pdfmetrics.registerFont(TTFont("Body", str(regular)))
        pdfmetrics.registerFont(TTFont("Body-Bold", str(bold)))
        return "Body", "Body-Bold"
    return "Helvetica", "Helvetica-Bold"


def _styles(body: str, bold: str) -> dict[str, Any]:
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle

    base = ParagraphStyle("base", fontName=body, fontSize=9, leading=12, alignment=TA_LEFT)
    return {
        "title": ParagraphStyle("title", parent=base, fontName=bold, fontSize=22, leading=26, spaceAfter=6),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base, fontSize=11, leading=14, textColor="#444444", spaceAfter=14
        ),
        "h1": ParagraphStyle(
            "h1", parent=base, fontName=bold, fontSize=14, leading=18, spaceBefore=12, spaceAfter=6
        ),
        "h2": ParagraphStyle(
            "h2", parent=base, fontName=bold, fontSize=11, leading=14, spaceBefore=10, spaceAfter=4
        ),
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=9.5),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.2, leading=8.8),
        "cellb": ParagraphStyle("cellb", parent=base, fontName=bold, fontSize=7.2, leading=8.8),
        "note": ParagraphStyle(
            "note",
            parent=base,
            fontSize=8,
            leading=10.5,
            textColor="#333333",
            backColor="#f3f1ea",
            borderPadding=6,
            spaceBefore=6,
            spaceAfter=10,
        ),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3),
    }


def _table(
    rows: list[list[str]], styles: dict[str, Any], widths: list[float], bold_first_col: bool = False
) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle

    data = []
    for i, row in enumerate(rows):
        cells = []
        for j, text in enumerate(row):
            style = styles["cellb"] if i == 0 or (bold_first_col and j == 0) else styles["cell"]
            cells.append(Paragraph(text, style))
        data.append(cells)
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e4d8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f6f2")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbbb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


def _short(text: str, limit: int = 40) -> str:
    """Abbreviate a long version string for the ranking table; the reproduction table keeps it whole."""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _esc(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _order(metrics: dict[str, Any], grades: dict[str, Any]) -> list[str]:
    ranked = grades.get("tools", {})
    return sorted(metrics["tools"], key=lambda n: (ranked.get(n, {}).get("rank", 99), n))


def build(corpus_path: Path, metrics: dict[str, Any], grades: dict[str, Any], out: Path) -> None:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    body, bold = _fonts()
    st = _styles(body, bold)
    corpus = load_corpus(corpus_path)
    m = metrics.get("manifest", {})
    n_cases = len(corpus.cases)
    n_expected = sum(len(c.expected) for c in corpus.cases)
    n_decoys = sum(len(c.decoys) for c in corpus.cases)
    run_date = str(m.get("started", ""))[:10]
    doc = SimpleDocTemplate(
        str(out),
        pagesize=landscape(A4),
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"ShadowBench {run_date}",
        author="Project Nexus (ShadowScan) maintainers",
        subject="Nine-surface shadow AI agent discovery benchmark: results and tool grades",
    )
    width = landscape(A4)[0] - 28 * mm
    story: list[Any] = []

    # --- title and summary -------------------------------------------------------
    story.append(Paragraph("ShadowBench", st["title"]))
    story.append(
        Paragraph(
            f"The nine-surface shadow AI agent discovery benchmark. Results and tool grades, run of {run_date}.",  # noqa: E501
            st["subtitle"],
        )
    )
    story.append(
        Paragraph(
            f"ShadowBench asks one question on every surface where shadow AI agents leave evidence: given what an operator "  # noqa: E501
            f"can collect from that surface, which AI agents and which plain AI uses are present, and can a discovery tool "  # noqa: E501
            f"find them without flagging the things that merely sound like AI? This run covered {n_cases} cases on nine "  # noqa: E501
            f"surfaces (code, identity, gateway, low-code, SaaS, cloud, endpoint, network, runtime) carrying {n_expected} "  # noqa: E501
            f"expected entities and {n_decoys} decoys. Nine tools ran; four more could not be exercised offline.",  # noqa: E501
            st["body"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            f"<b>Read this first.</b> {_esc(grades.get('caveat', ''))} The results show how each tool behaves on these "  # noqa: E501
            f"inputs. They do not estimate field precision or recall, and any ShadowScan lead is suspect until someone "  # noqa: E501
            f"without a stake reruns the benchmark. Corpus SHA-256 {_esc(metrics.get('corpus_sha256'))}; generator digest "  # noqa: E501
            f"{_esc(metrics.get('generator_digest'))}; platform {_esc(m.get('platform'))}.",
            st["note"],
        )
    )

    # --- ranking and grades ------------------------------------------------------
    story.append(Paragraph("1. Ranking and grades", st["h1"]))
    story.append(Paragraph(_esc(grades.get("rubric", "")), st["small"]))
    story.append(Spacer(1, 4))
    rows = [
        [
            "Rank",
            "Tool",
            "Version",
            "Surfaces run",
            "Estate recall",
            "In-scope P / R / F1",
            "Specificity on decoys",
            "Agent recall",
            "In-scope grade",
            "Program grade",
        ]
    ]
    for name in _order(metrics, grades):
        t = metrics["tools"][name]
        g = grades.get("tools", {}).get(name, {})
        i = t["in_scope"]
        rows.append(
            [
                str(g.get("rank", "")),
                _esc(name),
                _esc(_short(t.get("version") or "")),
                f"{t['coverage']}: {_esc(', '.join(t['surfaces_supported']))}",
                f"{pct(t['estate']['recall'])} ({t['estate']['tp']}/{t['estate']['expected']})",
                f"{pct(i['precision'])} / {pct(i['recall'])} / {pct(i['f1'])}{ci(i.get('f1_ci'))}",
                pct(i["specificity"]),
                f"{pct(i['agent_recall'])} ({i['agent_tp']}/{i['agent_expected']})",
                _esc(g.get("in_scope", "")),
                _esc(g.get("program", "")),
            ]
        )
    fr = [0.04, 0.11, 0.17, 0.17, 0.09, 0.14, 0.07, 0.09, 0.06, 0.06]
    story.append(_table(rows, st, [width * f for f in fr], bold_first_col=False))
    story.append(Spacer(1, 6))
    for name in _order(metrics, grades):
        g = grades.get("tools", {}).get(name)
        if g:
            story.append(
                Paragraph(
                    f"<b>{_esc(name)}</b> ({_esc(g.get('in_scope'))} / {_esc(g.get('program'))}): {_esc(g.get('rationale', ''))}",  # noqa: E501
                    st["bullet"],
                    bulletText="•",
                )
            )
    not_graded = grades.get("not_graded", {})
    if not_graded:
        story.append(
            Paragraph(
                "<b>Not graded</b> (no offline entry point): "
                + "; ".join(f"{_esc(k)}: {_esc(v)}" for k, v in not_graded.items())
                + ".",
                st["small"],
            )
        )
    story.append(Spacer(1, 10))

    # --- headline metrics --------------------------------------------------------
    story.append(Paragraph("2. Headline metrics", st["h1"]))
    story.append(
        Paragraph(
            "Estate recall counts every expected entity in the corpus, charging a tool for the surfaces it does not cover. "  # noqa: E501
            "In-scope metrics count only the surfaces and modalities a tool ran on. Specificity is measured on decoy entities. "  # noqa: E501
            "Agent recall is the share of expected agents a tool reported as agents; agent false alarms are plain-AI entities "  # noqa: E501
            "and decoys it called agents. F1 intervals are 2,000-sample case bootstraps. An error (crash, timeout, unreadable "  # noqa: E501
            "output) counts every expected entity as missed; an incomplete run is one the tool itself marked incomplete.",  # noqa: E501
            st["small"],
        )
    )
    story.append(Spacer(1, 4))
    rows = [
        [
            "Tool",
            "Surfaces",
            "Estate recall",
            "In-scope P / R / F1",
            "TP / FP / FN / TN",
            "Specificity",
            "Agent recall",
            "Agent false alarms",
            "Case balanced acc.",
            "Errors",
            "Incomplete",
            "Seconds med / p90",
        ]
    ]
    for name in _order(metrics, grades):
        t = metrics["tools"][name]
        i = t["in_scope"]
        rows.append(
            [
                _esc(name),
                t["coverage"],
                pct(t["estate"]["recall"]),
                f"{pct(i['precision'])} / {pct(i['recall'])} / {pct(i['f1'])}{ci(i.get('f1_ci'))}",
                f"{i['tp']} / {i['fp']} / {i['fn']} / {i['tn']}",
                pct(i["specificity"]),
                f"{pct(i['agent_recall'])} ({i['agent_tp']}/{i['agent_expected']})",
                f"{pct(i['agent_false_alarm_rate'])} ({i['agent_false_alarms']}/{i['agent_false_alarm_universe']})",  # noqa: E501
                pct(i["case"]["balanced_accuracy"]),
                str(i["errors"]),
                str(i["incomplete"]),
                f"{secs(i['seconds_median'])} / {secs(i['seconds_p90'])}",
            ]
        )
    fr = [0.12, 0.06, 0.08, 0.14, 0.11, 0.07, 0.09, 0.09, 0.08, 0.05, 0.05, 0.06]
    story.append(_table(rows, st, [width * f for f in fr], bold_first_col=True))
    story.append(Spacer(1, 10))

    # --- per surface -------------------------------------------------------------
    story.append(Paragraph("3. Results by surface", st["h1"]))
    for surface in SURFACES:
        info = metrics["surfaces"].get(surface)
        if not info or not info["cases"]:
            continue
        story.append(
            Paragraph(
                f"{surface}: {info['cases']} cases, {info['positives']} positive; {info['expected']} expected entities, "  # noqa: E501
                f"{info['decoys']} decoys; modalities {_esc(', '.join(info['modalities']))}",
                st["h2"],
            )
        )
        rows = [
            [
                "Tool",
                "Modalities",
                "P / R / F1",
                "TP / FP / FN / TN",
                "Specificity",
                "Agent recall",
                "Agent false alarms",
                "Case recall / specificity",
                "Errors",
                "Incomplete",
                "Seconds median",
            ]
        ]
        for name in _order(metrics, grades):
            s = metrics["tools"][name]["by_surface"].get(surface)
            if not s:
                continue
            c = s["case"]
            rows.append(
                [
                    _esc(name),
                    _esc(", ".join(s["modalities"])),
                    f"{pct(s['precision'])} / {pct(s['recall'])} / {pct(s['f1'])}{ci(s.get('f1_ci'))}",
                    f"{s['tp']} / {s['fp']} / {s['fn']} / {s['tn']}",
                    pct(s["specificity"]),
                    pct(s["agent_recall"]),
                    pct(s["agent_false_alarm_rate"]),
                    f"{pct(c['recall'])} / {pct(c['specificity'])}",
                    str(s["errors"]),
                    str(s["incomplete"]),
                    secs(s["seconds_median"]),
                ]
            )
        if len(rows) == 1:
            rows.append(["(no tool ran on this surface)"] + [""] * 10)
        fr = [0.13, 0.13, 0.14, 0.11, 0.07, 0.08, 0.09, 0.1, 0.05, 0.05, 0.05]
        story.append(_table(rows, st, [width * f for f in fr], bold_first_col=True))
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 10))

    # --- method ------------------------------------------------------------------
    story.append(Paragraph("4. Method", st["h1"]))
    method = [
        "<b>Cases and truth.</b> A case is one input a tool is pointed at: an identity-provider export (Okta apps with grants and "  # noqa: E501
        "tokens; Graph service principals, applications, permission grants and app-role assignments), a gateway log window "  # noqa: E501
        "(LiteLLM spend logs; Bedrock model invocation logs), a low-code export (Power Platform flows, apps, Copilot Studio bots "  # noqa: E501
        "and components; n8n workflows), a SaaS admin export (Slack approved apps, requests, users; GitHub App installations), "  # noqa: E501
        "a cloud account (AWS CLI outputs for STS, Bedrock Agents, AgentCore, Lambda, SageMaker, IAM; a Kubernetes workload list), "  # noqa: E501
        "a developer home directory, a workstation's Zeek logs or a set of loopback services, a host's osquery process table or "  # noqa: E501
        "live inert processes, or a pinned repository checkout. Every case lists expected entities with a label (agent or llm) "  # noqa: E501
        "and the evidence behind it, tolerated keys a tool may report without penalty, and decoys labeled none.",  # noqa: E501
        "<b>Labels.</b> agent: an autonomous or tool-using AI agent or an agent integration (a configured MCP server, Copilot "  # noqa: E501
        "Studio agent, Bedrock agent, coding-agent CLI, agent framework process). llm: AI use without agent evidence (a chat SaaS "  # noqa: E501
        "app, a model server, a single-completion caller, a GPT step in a flow). none: no AI, including service accounts without "  # noqa: E501
        "AI evidence, infrastructure agents, Minecraft Bedrock servers, apps named copilot, classic chatbots and plain workloads.",  # noqa: E501
        "<b>Matching.</b> A reported key matches an expected or decoy key when equal or, for home-directory artifacts, when one "  # noqa: E501
        "path is a parent directory of the other. Reported keys are de-duplicated. A key matching nothing expected or tolerated is "  # noqa: E501
        "a false positive; one hitting a decoy also counts against specificity. Code cases use the fact vocabulary of the "  # noqa: E501
        "code-surface benchmark (category:value), with provider facts labeled llm and all others agent.",
        "<b>Isolation.</b> Every tool runs as root in fresh network and PID namespaces with a minimal environment, a case-local "  # noqa: E501
        "HOME and no inherited credentials. Active-network cases serve mock products on loopback inside the tool's namespace; "  # noqa: E501
        "live-runtime cases spawn an inert static binary under each recorded process name and command line. No tool is given an "  # noqa: E501
        "allowlist, an inventory or a known-agent list. Verbatim tool output is kept beside the normalized entities.",  # noqa: E501
        "<b>Corpus construction.</b> Export-style cases draw entity families by quota (45% agent, 15% plain AI, 40% decoy, at least "  # noqa: E501
        "one decoy per export), redraw collisions and render the platform's own file shapes. Endpoint and passive-network cases "  # noqa: E501
        "reuse the pre-registered families of the earlier head-to-head benchmark. Code cases are 26 public repositories pinned by "  # noqa: E501
        "commit (16 positive, 4 control, 6 near-miss). The corpus records its seed and a SHA-256 over the generator sources; "  # noqa: E501
        "verify --regenerate rebuilds it byte for byte.",
        "<b>Bias controls.</b> Rubrics, families, generator, adapters and scoring were committed before the scored run; adapters "  # noqa: E501
        "were calibrated on probe inputs and a separate four-case-per-surface smoke corpus. Decoys come from the confusions real "  # noqa: E501
        "tools make. Tools are scored only on surfaces they declare; estate recall shows the cost of uncovered surfaces. A tool's "  # noqa: E501
        "own notion of a finding is used, with no confidence threshold imposed on top.",
        "<b>Limits.</b> Eight surfaces are synthetic and author-written; the code surface's labels are session-labeled evidence, "  # noqa: E501
        "not independent review. The same maintainer wrote ShadowScan, the rubrics and every adapter. Live-only tools without an "  # noqa: E501
        "offline entry point were not run. Mock services reproduce banners and version endpoints, not full applications. The "  # noqa: E501
        "gateway surface has no decoys. Twenty cases per modality give wide intervals.",
    ]
    for para in method:
        story.append(Paragraph(para, st["body"]))
        story.append(Spacer(1, 4))

    # --- reproduction ------------------------------------------------------------
    story.append(Paragraph("5. Reproduction", st["h1"]))
    story.append(
        Paragraph(
            f"Repository: github.com/aisecnomad/Nexus-ShadowScan, benchmarks/shadowbench and tools/shadowbench/synthetic. Corpus SHA-256 "  # noqa: E501
            f"{_esc(metrics.get('corpus_sha256'))}. Generator digest {_esc(metrics.get('generator_digest'))}. Run started "  # noqa: E501
            f"{_esc(m.get('started'))}, finished {_esc(m.get('finished'))}, {_esc(m.get('workers'))} parallel workers on "  # noqa: E501
            f"{_esc(m.get('platform'))}, Python {_esc(m.get('python'))}.",
            st["small"],
        )
    )
    story.append(Spacer(1, 4))
    rows = [["Tool", "Version or commit benchmarked"]]
    for name in _order(metrics, grades):
        rows.append([_esc(name), _esc(metrics["tools"][name].get("version") or "")])
    story.append(_table(rows, st, [width * 0.2, width * 0.8], bold_first_col=True))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Commands: python -m tools.shadowbench.synthetic verify --corpus benchmarks/shadowbench/synthetic/corpus.json --regenerate; "  # noqa: E501
            "bash tools/shadowbench/synthetic/install_tools.sh TOOL_ROOT; python tools/shadowbench/synthetic/fetch_code.py CHECKOUTS; "  # noqa: E501
            "python -m tools.shadowbench.synthetic run --corpus ... --tools tools.json --checkouts CHECKOUTS --out RESULTS; "  # noqa: E501
            "python -m tools.shadowbench.synthetic score ...; python -m tools.shadowbench.synthetic report ...; python -m tools.shadowbench.synthetic pdf ....",  # noqa: E501
            st["small"],
        )
    )
    doc.build(story)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--metrics", type=Path, required=True)
    ap.add_argument("--grades", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    grades = json.loads(args.grades.read_text(encoding="utf-8"))
    build(args.corpus, metrics, grades, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
