"""Unit tests for the ShadowBench cases-track scorer and report (tools/shadowbench/cases/score.py, report.py)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
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
    )


def _row(case: Case, status: str = "ok", keys: Iterable[str] = (), label: str = "agent") -> dict[str, Any]:
    return {
        "tool": "t",
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
        "incomplete": False,
    }


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
            "".join(json.dumps(r) + "\n" for r in tool_rows), encoding="utf-8"
        )
    manifest: dict[str, Any] = {
        "tools": manifest_tools if manifest_tools is not None else {t: {"version": "1"} for t in rows}
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
    assert score.main(_args(tmp_path, corpus_path, results)) != 0
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


# --- every case is scored; malformed results are refused (S2) -------------------------------------


def test_missing_rows_count_as_errors_not_as_absent_cases(tmp_path: Path) -> None:
    """A results file truncated to its first rows used to raise estate recall to the share it kept."""
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


def test_a_tool_the_manifest_ran_without_a_results_file_scores_as_all_missing(tmp_path: Path) -> None:
    case = _case("p1", expected=[("app:1", "agent")])
    corpus_path, results = _write(
        tmp_path,
        [case],
        {"t": [_row(case, keys=["app:1"])]},
        manifest_tools={
            "t": {"version": "1"},
            "gone": {"version": "2"},
            "skipped": {"skipped": "not installed"},
        },
    )
    tools = _score(tmp_path, corpus_path, results)["tools"]
    assert sorted(tools) == ["gone", "t"]
    assert (tools["gone"]["in_scope"]["missing"], tools["gone"]["estate"]["recall"]) == (1, 0.0)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda rows: [{**rows[0], "status": "timeout"}, *rows[1:]], "unknown status 'timeout'"),
        (lambda rows: [*rows, rows[0]], "second row for case"),
        (lambda rows: [*rows, {**rows[0], "case": "elsewhere"}], "'elsewhere' is not in the corpus"),
        (lambda rows: [{**rows[0], "surface": "gateway"}, *rows[1:]], "row surface 'gateway' disagrees"),
    ],
    ids=["unknown-status", "duplicate-row", "unknown-case", "surface-mismatch"],
)
def test_rows_that_cannot_be_scored_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mutate: Any, reason: str
) -> None:
    """Unknown statuses dropped whole surfaces, duplicates overwrote each other, unknown ids vanished."""
    cases = [_case("p1", expected=[("app:1", "agent")]), _case("n1", decoys=["app:d1"])]
    corpus_path, results = _write(
        tmp_path, cases, {"t": mutate([_row(cases[0], keys=["app:1"]), _row(cases[1])])}
    )
    assert reason in _refused(tmp_path, corpus_path, results, capsys)


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
