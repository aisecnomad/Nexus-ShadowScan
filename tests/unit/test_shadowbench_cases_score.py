"""Unit tests for the ShadowBench cases-track scorer and report (tools/shadowbench/cases/score.py, report.py)."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.shadowbench.cases import report, score
from tools.shadowbench.cases.contract import TruthEntity
from tools.shadowbench.cases.corpus import Case, Corpus, corpus_digest, dump_corpus, load_corpus

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "benchmarks" / "shadowbench" / "cases"
RUN = CASES / "results" / "2026-10-11"

# --- helpers --------------------------------------------------------------------------------------


def _case(
    cid: str,
    surface: str = "identity",
    modality: str = "okta-export",
    expected: Iterable[tuple[str, str]] = (),
    tolerated: Iterable[str] = (),
    decoys: Iterable[str] = (),
) -> Case:
    return Case(
        cid,
        surface,
        modality,
        "test-family",
        "easy",
        "unit test",
        expected=[TruthEntity(key.split(":", 1)[0], key, label, {}, "planted") for key, label in expected],
        tolerated=list(tolerated),
        decoys=list(decoys),
        # Code cases, and only code cases, carry a pinned checkout (corpus.validate_case).
        checkout={"id": cid, "host": "github.com", "path": f"example/{cid}", "commit": "0" * 40}
        if surface == "code"
        else None,
    )


def _row(
    case: Case, status: str = "ok", keys: Iterable[str] = (), label: str = "agent", incomplete: bool = False
) -> dict[str, Any]:
    """A runner row; ``_write`` stamps the tool of the file it goes to unless the row names one."""
    return {
        "case": case.case_id,
        "surface": case.surface,
        "modality": case.modality,
        "family": case.family,
        "label": case.label,
        "difficulty": case.difficulty,
        "status": status,
        "entities": [{"kind": "x", "key": k, "label": label} for k in keys],
        "note": "",
        "seconds": 0.5,
        "incomplete": incomplete,
    }


def _ran(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """The manifest entry the runner writes for a tool that produced ``rows``."""
    return {"version": "1", "statuses": dict(Counter(str(r["status"]) for r in rows))}


def _write(
    tmp_path: Path,
    cases: list[Case],
    rows: dict[str, list[dict[str, Any]]],
    manifest_tools: dict[str, Any] | None = None,
    corpus_sha256: str | None = "match",
) -> tuple[Path, Path]:
    corpus_path = tmp_path / "corpus.json"
    digest = dump_corpus(Corpus(cases, 1, "generator", "2026-10-11T00:00:00Z"), corpus_path)
    results = tmp_path / "results"
    results.mkdir()
    for tool, tool_rows in rows.items():
        (results / f"{tool}.jsonl").write_text(
            "".join(json.dumps({"tool": tool, **r}) + "\n" for r in tool_rows), encoding="utf-8"
        )
    manifest: dict[str, Any] = {
        "tools": manifest_tools if manifest_tools is not None else {t: _ran(r) for t, r in rows.items()}
    }
    if corpus_sha256 is not None:
        manifest["corpus_sha256"] = digest if corpus_sha256 == "match" else corpus_sha256
    (results / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return corpus_path, results


def _args(tmp_path: Path, corpus_path: Path, results: Path, *extra: str) -> list[str]:
    out = tmp_path / "metrics.json"
    return ["--corpus", str(corpus_path), "--results", str(results), "--out", str(out), *extra]


def _score(tmp_path: Path, corpus_path: Path, results: Path, *extra: str) -> dict[str, Any]:
    assert score.main(_args(tmp_path, corpus_path, results, *extra)) == 0
    metrics: dict[str, Any] = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    return metrics


def _refused(tmp_path: Path, corpus_path: Path, results: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert score.main(_args(tmp_path, corpus_path, results)) == 2
    assert not (tmp_path / "metrics.json").exists()
    return capsys.readouterr().err


# --- errors are never a correct outcome (S1) ------------------------------------------------------


def test_error_on_a_negative_case_is_a_false_alarm_not_a_true_negative(tmp_path: Path) -> None:
    """An errored negative case used to count as a correct negative and raised case specificity."""
    pos = _case("p1", expected=[("app:1", "agent")])
    clean = _case("n1", decoys=["app:d1"])
    broken = _case("n2", decoys=["app:d2"])
    corpus_path, results = _write(
        tmp_path, [pos, clean, broken], {"t": [_row(pos, keys=["app:1"]), _row(clean), _row(broken, "error")]}
    )
    i = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]
    assert i["errors"] == 1
    assert (i["case"]["tp"], i["case"]["fn"], i["case"]["fp"], i["case"]["tn"]) == (1, 0, 1, 1)
    assert i["case"]["specificity"] == 0.5
    assert i["case"]["balanced_accuracy"] == 0.75
    assert i["case"]["mcc"] == 0.5
    # the errored case's decoy is not a true negative and stays in the specificity denominator
    assert (i["tn"], i["decoys"], i["fp"]) == (1, 2, 0)
    assert i["specificity"] == 0.5


def test_error_on_a_positive_case_is_a_miss(tmp_path: Path) -> None:
    pos = _case("p1", expected=[("app:1", "agent")])
    neg = _case("n1", decoys=["app:d1"])
    corpus_path, results = _write(tmp_path, [pos, neg], {"t": [_row(pos, "error"), _row(neg)]})
    i = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]
    assert (i["case"]["tp"], i["case"]["fn"], i["case"]["tn"]) == (0, 1, 1)
    assert (i["tp"], i["fn"]) == (0, 1)


def test_an_incomplete_scan_never_earns_a_true_negative(tmp_path: Path) -> None:
    """An incomplete scan that reported nothing used to count as a clean negative, its decoys as TNs."""
    pos = _case("p1", expected=[("app:1", "agent"), ("app:2", "llm")], decoys=["app:d0"])
    clean = _case("n1", decoys=["app:d1"])
    partial = _case("n2", decoys=["app:d2", "app:d3"])
    corpus_path, results = _write(
        tmp_path,
        [pos, clean, partial],
        {
            "t": [
                # app:2 is plain AI reported as an agent: an agent false alarm the scan did make
                _row(pos, keys=["app:1", "app:2"], incomplete=True),
                _row(clean),
                _row(partial, incomplete=True),
            ]
        },
    )
    metrics = _score(tmp_path, corpus_path, results)
    i = metrics["tools"]["t"]["in_scope"]
    assert i["incomplete"] == 2
    # what the incomplete scans reported still counts
    assert (i["tp"], i["fp"], i["fn"]) == (2, 0, 0)
    assert (i["case"]["tp"], i["case"]["fn"]) == (1, 0)
    # the incomplete negative is a false alarm, not a correct negative
    assert (i["case"]["tn"], i["case"]["fp"], i["case"]["specificity"]) == (1, 1, 0.5)
    assert i["case"]["balanced_accuracy"] == 0.75
    # only the complete scan's decoy is a true negative; the others stay in the denominator
    assert (i["tn"], i["decoys"], i["specificity"]) == (1, 4, 0.25)
    # incomplete scans add only the false alarms they made to the agent false-alarm universe
    assert (i["agent_false_alarms"], i["agent_false_alarm_universe"]) == (1, 2)
    assert "never earns a true negative" in report.render(metrics, corpus_path)


# --- every case is scored; malformed results are refused (S2) -------------------------------------


def test_missing_rows_count_as_errors_not_as_absent_cases(tmp_path: Path) -> None:
    """A run of only some cases (runner ``--cases``) used to raise estate recall to the share it ran."""
    cases = [_case(f"p{i}", expected=[(f"app:{i}", "agent")]) for i in range(4)]
    corpus_path, results = _write(
        tmp_path, cases, {"t": [_row(c, keys=[f"app:{n}"]) for n, c in enumerate(cases[:2])]}
    )
    metrics = _score(tmp_path, corpus_path, results)
    t = metrics["tools"]["t"]
    assert t["estate"] == {"expected": 4, "tp": 2, "recall": 0.5}
    assert (t["in_scope"]["errors"], t["in_scope"]["missing"], t["in_scope"]["recall"]) == (2, 2, 0.5)
    assert t["in_scope"]["case"]["fn"] == 2
    assert "| 2 (2 missing) |" in report.render(metrics, corpus_path)


def test_a_results_file_truncated_after_the_run_is_refused_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The manifest counted four rows; a file cut to two no longer matches the run that wrote it."""
    cases = [_case(f"p{i}", expected=[(f"app:{i}", "agent")]) for i in range(4)]
    full = [_row(c, keys=[f"app:{n}"]) for n, c in enumerate(cases)]
    corpus_path, results = _write(tmp_path, cases, {"t": full[:2]}, manifest_tools={"t": _ran(full)})
    assert "row statuses {'ok': 2} differ from the {'ok': 4}" in _refused(
        tmp_path, corpus_path, results, capsys
    )
    metrics = _score(tmp_path, corpus_path, results, "--force")
    t = metrics["tools"]["t"]
    assert (t["in_scope"]["missing"], t["estate"]["recall"]) == (2, 0.5)
    assert len(metrics["forced"]) == 1


def test_a_tool_the_manifest_ran_without_a_results_file_is_refused_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _case("p1", expected=[("app:1", "agent")])
    rows = [_row(case, keys=["app:1"])]
    corpus_path, results = _write(
        tmp_path,
        [case],
        {"t": rows},
        manifest_tools={"t": _ran(rows), "gone": _ran(rows), "skipped": {"skipped": "not installed"}},
    )
    assert "gone.jsonl: row statuses {} differ" in _refused(tmp_path, corpus_path, results, capsys)
    tools = _score(tmp_path, corpus_path, results, "--force")["tools"]
    assert sorted(tools) == ["gone", "t"]
    assert (tools["gone"]["in_scope"]["missing"], tools["gone"]["estate"]["recall"]) == (1, 0.0)


def test_a_results_file_for_a_tool_the_manifest_skipped_is_refused_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file left behind by an earlier run (the runner never clears ``--out``) used to be scored."""
    case = _case("p1", expected=[("app:1", "agent")])
    rows = [_row(case, keys=["app:1"])]
    corpus_path, results = _write(
        tmp_path,
        [case],
        {"shadowscan": rows, "rival": rows},
        manifest_tools={"shadowscan": _ran(rows), "rival": {"skipped": "binary not found"}},
    )
    assert "records rival as not run (binary not found)" in _refused(tmp_path, corpus_path, results, capsys)
    metrics = _score(tmp_path, corpus_path, results, "--force")
    assert metrics["forced"] == ["rival.jsonl: the manifest records rival as not run (binary not found)"]
    text = report.render(metrics, corpus_path)
    assert "scored with `--force` over these refusals" in text
    assert "- `rival`: binary not found (a results file for it was scored with `--force`)" in text


def test_a_results_file_for_a_tool_the_manifest_does_not_list_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--only`` rewrites the manifest with the tools it ran; other files in ``--out`` are not this run's."""
    case = _case("p1", expected=[("app:1", "agent")])
    rows = [_row(case, keys=["app:1"])]
    corpus_path, results = _write(
        tmp_path, [case], {"shadowscan": rows, "rival": rows}, manifest_tools={"shadowscan": _ran(rows)}
    )
    assert "the manifest does not list rival" in _refused(tmp_path, corpus_path, results, capsys)


def test_a_manifest_without_row_statuses_for_a_tool_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _case("p1", expected=[("app:1", "agent")])
    corpus_path, results = _write(
        tmp_path, [case], {"t": [_row(case, keys=["app:1"])]}, manifest_tools={"t": {"version": "1"}}
    )
    assert "records no row statuses" in _refused(tmp_path, corpus_path, results, capsys)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda rows: [{**rows[0], "status": "timeout"}, *rows[1:]], "unknown status 'timeout'"),
        (lambda rows: [*rows, rows[0]], "second row for case"),
        (lambda rows: [*rows, {**rows[0], "case": "elsewhere"}], "'elsewhere' is not in the corpus"),
        (lambda rows: [{**rows[0], "surface": "gateway"}, *rows[1:]], "row surface 'gateway' disagrees"),
        (lambda rows: [rows[0], {**rows[1], "label": "agent"}], "row label 'agent' disagrees"),
        (lambda rows: [{**rows[0], "family": "old-family"}, *rows[1:]], "row family 'old-family' disagrees"),
        (lambda rows: [{**rows[0], "difficulty": "hard"}, *rows[1:]], "row difficulty 'hard' disagrees"),
        (
            lambda rows: [{k: v for k, v in rows[0].items() if k != "family"}, *rows[1:]],
            "row family None disagrees",
        ),
        (lambda rows: [{**rows[0], "tool": "rival"}, *rows[1:]], "row tool 'rival' is not the file's"),
    ],
    ids=[
        "unknown-status",
        "duplicate-row",
        "unknown-case",
        "surface-mismatch",
        "label-mismatch",
        "family-mismatch",
        "difficulty-mismatch",
        "family-absent",
        "tool-mismatch",
    ],
)
def test_rows_that_cannot_be_scored_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mutate: Any, reason: str
) -> None:
    """Unknown statuses dropped whole surfaces, duplicates overwrote each other, unknown ids vanished.

    Case ids are positional, so a row from another seed's corpus carries a matching surface and
    modality; its family, label or difficulty is what gives it away.
    """
    cases = [_case("p1", expected=[("app:1", "agent")]), _case("n1", decoys=["app:d1"])]
    corpus_path, results = _write(
        tmp_path, cases, {"t": mutate([_row(cases[0], keys=["app:1"]), _row(cases[1])])}
    )
    assert reason in _refused(tmp_path, corpus_path, results, capsys)


def test_an_unsupported_row_among_scored_rows_of_one_modality_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One positive marked unsupported used to vanish from in-scope recall with zero errors."""
    p1, p2 = _case("p1", expected=[("app:1", "agent")]), _case("p2", expected=[("app:2", "agent")])
    neg = _case("n1", decoys=["app:d1"])
    corpus_path, results = _write(
        tmp_path, [p1, p2, neg], {"t": [_row(p1, keys=["app:1"]), _row(p2, "unsupported"), _row(neg)]}
    )
    err = _refused(tmp_path, corpus_path, results, capsys)
    assert "identity/okta-export has unsupported rows alongside ok or error rows" in err


def test_results_from_another_corpus_are_refused_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _case("p1", expected=[("app:1", "agent")])
    corpus_path, results = _write(
        tmp_path, [case], {"t": [_row(case, keys=["app:1"])]}, corpus_sha256="0" * 64
    )
    assert "recorded against corpus 0000" in _refused(tmp_path, corpus_path, results, capsys)
    metrics = _score(tmp_path, corpus_path, results, "--force")
    assert metrics["corpus_mismatch_forced"] is True
    assert metrics["corpus_sha256"] == "0" * 64
    assert "scored with `--force`" in report.render(metrics, corpus_path)


def test_results_without_a_corpus_digest_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _case("p1", expected=[("app:1", "agent")])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case, keys=["app:1"])]}, corpus_sha256=None)
    assert "(not recorded)" in _refused(tmp_path, corpus_path, results, capsys)


# --- artifact matching is one-way; tolerated keys come first (S3) ---------------------------------

OLLAMA = "artifact:.ollama/models/manifests/registry.ollama.ai/library/llama3.1/8b"


def _endpoint(**kw: Any) -> Case:
    return _case("e1", surface="endpoint", modality="home", **kw)


def _endpoint_counts(tmp_path: Path, case: Case, keys: list[str]) -> tuple[int, int]:
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case, keys=keys)]})
    i = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]
    return i["tp"], i["fp"]


def test_a_tolerated_ancestor_of_an_expected_file_is_not_credited(tmp_path: Path) -> None:
    """Reporting the Ollama manifests directory used to score the manifest file it contains."""
    case = _endpoint(
        expected=[(OLLAMA, "llm")],
        tolerated=["artifact:.ollama", "artifact:.ollama/models", "artifact:.ollama/models/manifests"],
    )
    assert _endpoint_counts(tmp_path, case, ["artifact:.ollama/models/manifests"]) == (0, 0)


def test_an_untolerated_ancestor_of_an_expected_file_is_a_false_positive(tmp_path: Path) -> None:
    case = _endpoint(expected=[("artifact:.config/Claude/claude_desktop_config.json", "agent")])
    assert _endpoint_counts(tmp_path, case, ["artifact:.config"]) == (0, 1)


def test_an_exact_tolerated_key_wins_over_an_expected_directory(tmp_path: Path) -> None:
    case = _endpoint(expected=[("artifact:.claude", "agent")], tolerated=["artifact:.claude/settings.json"])
    assert _endpoint_counts(tmp_path, case, ["artifact:.claude/settings.json"]) == (0, 0)


def test_a_file_inside_an_expected_directory_is_credited(tmp_path: Path) -> None:
    case = _endpoint(expected=[("artifact:.openclaw", "agent")])
    assert _endpoint_counts(tmp_path, case, ["artifact:.openclaw/openclaw.json"]) == (1, 0)


# --- case-level outcomes need a true positive, or a false positive (S4) ---------------------------


def test_a_positive_case_with_only_false_positives_is_not_found(tmp_path: Path) -> None:
    """A tool that reported anything on a positive home used to count as having found it."""
    case = _endpoint(expected=[("artifact:.cursor/mcp.json", "agent")])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case, keys=["artifact:.vscode"])]})
    c = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]["case"]
    assert (c["tp"], c["fn"], c["recall"]) == (0, 1, 0.0)


def test_a_negative_case_with_only_tolerated_reports_is_not_a_false_alarm(tmp_path: Path) -> None:
    case = _case("n1", tolerated=["app:support"], decoys=["app:d1"])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case, keys=["app:support"])]})
    c = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]["case"]
    assert (c["tn"], c["fp"]) == (1, 0)


# --- code keys outside the fact taxonomy are ignored for every tool (S5) --------------------------


def test_code_keys_outside_the_taxonomy_are_neither_true_nor_false_positives(tmp_path: Path) -> None:
    """An adapter that passed unmappable file paths through used to collect a false positive for each."""
    pos = _case("c1", surface="code", modality="checkout", expected=[("framework:langchain", "agent")])
    neg = _case("c2", surface="code", modality="checkout")
    corpus_path, results = _write(
        tmp_path,
        [pos, neg],
        {
            "t": [
                _row(pos, keys=["framework:langchain", "artifact:examples/agents.py", "provider:openai"]),
                _row(neg, keys=["artifact:tests/test_agents.py"]),
            ]
        },
    )
    metrics = _score(tmp_path, corpus_path, results)
    i = metrics["tools"]["t"]["in_scope"]
    # only provider:openai, a taxonomy fact the truth does not list, is a false positive
    assert (i["tp"], i["fp"]) == (1, 1)
    assert (i["case"]["tn"], i["case"]["fp"]) == (1, 0)
    assert i["out_of_taxonomy"] == 2
    assert metrics["tools"]["t"]["by_surface"]["code"]["out_of_taxonomy"] == 2
    assert "outside the code fact taxonomy" in report.render(metrics, corpus_path)


def test_artifact_keys_outside_the_code_surface_are_still_scored(tmp_path: Path) -> None:
    """The taxonomy rule is for code truth only: an unknown home-directory path stays a false positive."""
    case = _endpoint(expected=[("artifact:.cursor/mcp.json", "agent")])
    corpus_path, results = _write(
        tmp_path, [case], {"t": [_row(case, keys=["artifact:.cursor/mcp.json", "artifact:x"])]}
    )
    i = _score(tmp_path, corpus_path, results)["tools"]["t"]["in_scope"]
    assert (i["tp"], i["fp"], i["out_of_taxonomy"]) == (1, 1, 0)


def test_a_code_truth_key_outside_the_taxonomy_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case = _case("c1", surface="code", modality="checkout", expected=[("artifact:agent.py", "agent")])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case)]})
    assert "not a taxonomy fact" in _refused(tmp_path, corpus_path, results, capsys)


# --- decoys an adapter never passes to its tool ---------------------------------------------------

IAM = "resource:arn:aws:iam::123456789012:role/nightly-backup"
LAMBDA = "resource:arn:aws:lambda:us-east-1:123456789012:function:resize-images"
AGENT = "resource:arn:aws:bedrock:us-east-1:123456789012:agent/AGENT0001"


def _aws(cid: str, expected: Iterable[tuple[str, str]] = (), decoys: Iterable[str] = ()) -> Case:
    return _case(cid, "cloud", "aws-export", expected=expected, decoys=decoys)


def test_a_decoy_the_adapter_withholds_is_not_a_true_negative(tmp_path: Path) -> None:
    """ShadowScan's adapter never converts IAM roles, yet each IAM-role decoy was a ShadowScan TN."""
    case = _aws("a1", expected=[(AGENT, "agent")], decoys=[IAM, LAMBDA])
    # the tool flags the one decoy it was shown, so its specificity is 0, not the 50% the IAM role gave
    rows = [_row(case, keys=[AGENT, LAMBDA])]
    corpus_path, results = _write(tmp_path, [case], {"shadowscan": rows, "other": rows})
    metrics = _score(tmp_path, corpus_path, results)
    ss = metrics["tools"]["shadowscan"]
    surface = ss["by_surface"]["cloud"]
    for entry in (ss["in_scope"], surface, surface["modalities"]["aws-export"]):
        assert (entry["tn"], entry["decoys"], entry["specificity"]) == (0, 1, 0.0)
        assert (entry["fp"], entry["decoys_withheld"]) == (1, 1)
    # the withheld decoy is not in the agent false-alarm universe either
    assert (ss["in_scope"]["agent_false_alarms"], ss["in_scope"]["agent_false_alarm_universe"]) == (1, 1)
    assert ss["withheld_decoys"] == {"cloud/aws-export": ["resource:arn:aws:iam::"]}
    # a tool whose adapter declares nothing is scored on every decoy, as before
    other = metrics["tools"]["other"]["in_scope"]
    assert (other["tn"], other["decoys"], other["specificity"], other["decoys_withheld"]) == (1, 2, 0.5, 0)
    assert metrics["tools"]["other"]["withheld_decoys"] == {}
    text = report.render(metrics, corpus_path)
    assert "shadowscan, 1 decoy (cloud/aws-export, keys starting `resource:arn:aws:iam::`)" in text


def test_a_withheld_decoy_the_tool_reports_anyway_counts_against_it(tmp_path: Path) -> None:
    case = _aws("a1", decoys=[IAM, LAMBDA])
    corpus_path, results = _write(tmp_path, [case], {"shadowscan": [_row(case, keys=[IAM])]})
    i = _score(tmp_path, corpus_path, results)["tools"]["shadowscan"]["in_scope"]
    assert (i["fp"], i["tn"], i["decoys"], i["decoys_withheld"]) == (1, 1, 2, 0)
    assert (i["agent_false_alarms"], i["agent_false_alarm_universe"]) == (1, 2)
    assert (i["case"]["negatives"], i["case"]["fp"]) == (1, 1)


def test_withheld_decoys_of_an_error_row_leave_the_denominator(tmp_path: Path) -> None:
    case = _aws("a1", decoys=[IAM, LAMBDA])
    corpus_path, results = _write(tmp_path, [case], {"shadowscan": [_row(case, "error")]})
    i = _score(tmp_path, corpus_path, results)["tools"]["shadowscan"]["in_scope"]
    # the error still earns no true negative on the decoy the tool was given
    assert (i["tn"], i["decoys"], i["decoys_withheld"], i["specificity"]) == (0, 1, 1, 0.0)
    assert (i["case"]["negatives"], i["case"]["fp"]) == (1, 1)


def test_a_negative_case_whose_every_decoy_was_withheld_is_no_case_outcome(tmp_path: Path) -> None:
    """A clean scan of an export the tool was shown nothing of is not a correct negative."""
    blind = _aws("a1", decoys=[IAM])
    shown = _aws("a2", decoys=[LAMBDA])
    corpus_path, results = _write(
        tmp_path,
        [blind, shown],
        {"shadowscan": [_row(blind), _row(shown)], "other": [_row(blind), _row(shown)]},
    )
    metrics = _score(tmp_path, corpus_path, results)
    case_level = metrics["tools"]["shadowscan"]["in_scope"]["case"]
    assert (case_level["negatives"], case_level["negatives_withheld"], case_level["tn"]) == (1, 1, 1)
    assert metrics["tools"]["other"]["in_scope"]["case"]["negatives"] == 2
    # the paired comparison leaves out the case the reference was shown nothing of
    assert metrics["tools"]["other"]["vs_reference"]["shared"] == 1
    assert "shadowscan, 1 decoy and 1 negative case (" in report.render(metrics, corpus_path)


def test_a_negative_case_with_every_decoy_withheld_stays_a_false_alarm_when_it_fails(tmp_path: Path) -> None:
    """Fail closed: an error, an incomplete scan or a false positive there is still a false alarm."""
    cases = [_aws(f"a{i}", decoys=[IAM]) for i in range(3)]
    rows = [_row(cases[0], "error"), _row(cases[1], incomplete=True), _row(cases[2], keys=[LAMBDA])]
    corpus_path, results = _write(tmp_path, cases, {"shadowscan": rows})
    case_level = _score(tmp_path, corpus_path, results)["tools"]["shadowscan"]["in_scope"]["case"]
    assert (case_level["negatives"], case_level["negatives_withheld"], case_level["fp"]) == (3, 0, 3)


def test_an_adapter_module_that_does_not_load_is_refused_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """What a broken adapter withholds is unknown, so its tool's true negatives cannot be trusted."""
    monkeypatch.setattr(score, "load_adapters", lambda: ({}, {"broken": "ImportError: no module"}))
    case = _aws("a1", decoys=[LAMBDA])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case)]})
    assert "adapter module broken does not load" in _refused(tmp_path, corpus_path, results, capsys)
    metrics = _score(tmp_path, corpus_path, results, "--force")
    assert any("adapter module broken" in problem for problem in metrics["forced"])


@pytest.mark.parametrize(
    "declared",
    [
        [("cloud", "aws-export")],
        {("cloud",): ("resource:",)},
        {("cloud", "aws-export"): ()},
        {("cloud", "aws-export"): ("",)},
        {("cloud", "aws-export"): "resource:arn:aws:iam::"},
    ],
)
def test_a_malformed_withheld_declaration_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, declared: object
) -> None:
    adapter = SimpleNamespace(name="t", withheld_decoys=declared)
    monkeypatch.setattr(score, "load_adapters", lambda: ({"t": adapter}, {}))
    case = _aws("a1", decoys=[LAMBDA])
    corpus_path, results = _write(tmp_path, [case], {"t": [_row(case)]})
    assert "withheld_decoys" in _refused(tmp_path, corpus_path, results, capsys)


# --- paired comparison (S6) -----------------------------------------------------------------------


def test_mcnemar_with_no_shared_case_is_not_applicable(tmp_path: Path) -> None:
    """Two tools that never ran on the same case used to print p = 1.000."""
    a = _case("p1", expected=[("app:1", "agent")])
    b = _case("p2", surface="gateway", modality="litellm-export", expected=[("caller:x", "agent")])
    corpus_path, results = _write(
        tmp_path,
        [a, b],
        {
            "shadowscan": [_row(a, keys=["app:1"]), _row(b, "unsupported")],
            "other": [_row(a, "unsupported"), _row(b, keys=["caller:x"])],
        },
    )
    metrics = _score(tmp_path, corpus_path, results)
    v = metrics["tools"]["other"]["vs_reference"]
    assert v["mcnemar_p"] is None
    assert v["shared"] == 0
    assert "| other | shadowscan | 0 | 0 | 0 | n/a |" in report.render(metrics, corpus_path)


def test_mcnemar_with_shared_cases_and_no_discordant_pair_is_one(tmp_path: Path) -> None:
    a = _case("p1", expected=[("app:1", "agent")])
    corpus_path, results = _write(
        tmp_path, [a], {"shadowscan": [_row(a, keys=["app:1"])], "other": [_row(a, keys=["app:1"])]}
    )
    metrics = _score(tmp_path, corpus_path, results)
    v = metrics["tools"]["other"]["vs_reference"]
    assert (v["shared"], v["mcnemar_p"]) == (1, 1.0)
    assert "| other | shadowscan | 1 | 0 | 0 | 1.000 |" in report.render(metrics, corpus_path)


# --- the committed run ----------------------------------------------------------------------------


def test_committed_metrics_and_report_are_what_the_scorer_produces() -> None:
    """The published numbers must be re-derivable from the committed rows with the committed scorer."""
    corpus_path = CASES / "corpus.json"
    metrics = score.score(load_corpus(corpus_path), RUN, corpus_sha256=corpus_digest(corpus_path))
    committed = json.loads((RUN / "metrics.json").read_text(encoding="utf-8"))
    assert json.loads(json.dumps(metrics)) == committed
    assert report.render(committed, corpus_path) == (RUN / "REPORT.md").read_text(encoding="utf-8")
