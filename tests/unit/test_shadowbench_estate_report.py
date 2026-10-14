"""Regression tests for the estate report's claims and the numbers behind them
(tools/shadowbench/estate/score.py, report.py and __main__.py).

- The report said the ground truth was "frozen before any tool ran"; the README protocol has
  every runnable tool run once in a label-completeness audit, which added a secondary anchor
  and a tolerated pair, before the freeze.
- F1 was computed from precision and recall already rounded to four places, so published F1
  values were off in the fourth place.
- An unattributed prediction was charged in the in-scope and estate-wide value numbers but in
  no per-surface cell, so the cells reported no false positive where the totals charged one.
- `score` ignored the freeze record a run carries (drift during the run, the freeze manifest's
  digest) and dropped it and the harness revision from the metrics and the report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.estate import report, score
from tools.shadowbench.estate.__main__ import cmd_freeze, main
from tools.shadowbench.estate.corpus import EstateCorpus, corpus_from_dict, load_corpus, sha256_file

ROOT = Path(__file__).resolve().parents[2]
TRACK = ROOT / "benchmarks" / "shadowbench" / "estate"
RESULTS = TRACK / "results" / "2026-10-11"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _words(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def committed(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, Any], str]:
    """The committed run scored and rendered by the current code."""
    out = tmp_path_factory.mktemp("committed")
    corpus = str(TRACK / "corpus.json")
    argv = [
        "score",
        "--corpus",
        corpus,
        "--estate",
        str(TRACK / "artifacts"),
        "--runs",
        str(RESULTS / "runs.json"),
    ]
    assert main([*argv, "--out", str(out / "m.json")]) == 0
    assert (
        main(["report", "--corpus", corpus, "--metrics", str(out / "m.json"), "--out", str(out / "r.md")])
        == 0
    )
    metrics = json.loads((out / "m.json").read_text(encoding="utf-8"))
    return metrics, (out / "r.md").read_text(encoding="utf-8")


# --- the provenance sentence ----------------------------------------------------------------------


def test_report_gives_the_readme_protocol_order(committed: tuple[dict[str, Any], str]) -> None:
    readme = _words((TRACK / "README.md").read_text(encoding="utf-8"))
    for step in (
        "Every runnable tool ran once",
        "one secondary anchor, and one corpus-level tolerated pair",
        "4. **Freeze.**",
        "The published run was produced after the original freeze.",
    ):
        assert step in readme
    rendered = _words(committed[1])
    assert "frozen before any tool ran" not in rendered
    assert "checked only to parse cleanly in ShadowScan's offline loaders" in rendered
    audit = rendered.index("in one label-completeness audit, every runnable tool ran once")
    added = rendered.index("added one secondary anchor and one corpus-level tolerated pair")
    frozen = rendered.index("The corpus was frozen after that audit")
    scored = rendered.index("the scored run came after the freeze")
    assert audit < added < frozen < scored


# --- F1 from the counts ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tp", "fp", "fn", "f1"),
    [
        (1, 0, 18, 0.1),  # rounded P and R gave 0.0999
        (2, 0, 21, 0.16),  # 0.1601
        (3, 0, 20, 0.2308),  # 0.2307
        (8, 0, 96, 0.1429),  # 0.1428
        (0, 2, 3, 0.0),
        (0, 0, 3, None),
        (0, 2, 0, None),
        (0, 0, 0, None),
    ],
)
def test_f1_is_computed_from_the_counts(tp: int, fp: int, fn: int, f1: float | None) -> None:
    assert score.Counts(tp=tp, fp=fp, fn=fn).f1 == f1


def test_committed_metrics_f1_matches_the_counts() -> None:
    metrics = json.loads((RESULTS / "metrics.json").read_text(encoding="utf-8"))
    blocks: list[dict[str, Any]] = []

    def collect(node: object) -> None:
        if isinstance(node, dict):
            if {"tp", "fp", "fn", "f1"} <= node.keys():
                blocks.append(node)
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    collect(metrics)
    assert blocks
    for block in blocks:
        assert block["f1"] == score.Counts(tp=block["tp"], fp=block["fp"], fn=block["fn"]).f1, block


# --- unattributed predictions in the per-surface cells --------------------------------------------


def _entity(entity_id: str, surface: str, anchor: str, fact: str) -> dict[str, Any]:
    return {
        "id": entity_id,
        "surface": surface,
        "class": "positive",
        "difficulty": "easy",
        "unit": "estate",
        "expected": [{"fact": fact, "evidence": [f"{surface}/a.json"]}],
        "tolerated": [],
        "anchors": [anchor],
        "artifacts": [f"{surface}/a.json"],
    }


def _corpus() -> EstateCorpus:
    return corpus_from_dict(
        {
            "schema": 1,
            "metadata": {},
            "entities": [
                _entity("endpoint.cursor", "endpoint", "cursor-anchor", "ai-client:cursor"),
                _entity("code.mcp", "code", "mcp-anchor", "mcp:server"),
            ],
        }
    )


def _run(*predictions: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "inv",
        "unit": "estate",
        "status": "ok",
        "seconds": 0.1,
        "predictions": list(predictions),
        "commands": [{"argv": ["inv"], "exit_code": 0, "ok": True, "timed_out": False}],
        "error": None,
        "incomplete": False,
    }


def _metrics(*predictions: dict[str, Any], surfaces: tuple[str, ...] = ("endpoint",)) -> dict[str, Any]:
    specs = {"inv": {"name": "Inv", "surfaces": list(surfaces)}}
    return score.score_all(_corpus(), {"results": [_run(*predictions)]}, specs)


def test_unattributed_prediction_is_charged_in_its_surface_cell() -> None:
    metrics = _metrics(
        {"fact": "ai-client:cursor", "text": "names no anchor", "surface": "endpoint"},
        {"fact": "ai-client:cursor", "text": "no surface given either"},
    )
    level = metrics["tools"]["inv"]["value_level"]
    assert level["by_surface"]["endpoint"] == level["in_scope"]
    assert (level["in_scope"]["tp"], level["in_scope"]["fp"], level["in_scope"]["fn"]) == (0, 2, 1)
    assert level["unplaced_fp"] == 0
    rendered = report.render(metrics, _corpus(), title="t")
    assert "| Inv | out of scope (0/0/1) | " in rendered
    assert "| 0% (0/2/1) |" in rendered
    assert "no single surface holds" not in rendered


def test_unattributed_prediction_on_several_surfaces_is_counted_as_unplaced() -> None:
    # `mcp` lives on code and endpoint; with no surface of its own it belongs to neither cell.
    metrics = _metrics({"fact": "mcp:server", "text": "names no anchor"}, surfaces=("code", "endpoint"))
    level = metrics["tools"]["inv"]["value_level"]
    assert all(cell["fp"] == 0 for cell in level["by_surface"].values())
    assert level["unplaced_fp"] == 1 and level["all"]["fp"] == 1 and level["in_scope"]["fp"] == 1
    rendered = report.render(metrics, _corpus(), title="t")
    assert "charged as false positives in the value totals but in no cell above: Inv 1." in rendered


def test_committed_live_sim_without_the_appended_anchors_charges_the_runtime_cell() -> None:
    """README disclosure [a]: without the answer-key anchors both predictions are false positives."""
    corpus = load_corpus(TRACK / "corpus.json")
    services = score.load_services(TRACK / "artifacts" / "services" / "services.json")
    manifest = json.loads((RESULTS / "runs.json").read_text(encoding="utf-8"))
    [row] = [row for row in manifest["results"] if row["tool"] == "ai_infra_guard"]
    anchors = [f" {anchor}" for anchor in services.values()]
    stripped = []
    for prediction in row["predictions"]:
        text = prediction["text"]
        for anchor in anchors:
            text = text.replace(anchor, "")
        stripped.append({**prediction, "text": text})
    specs = {"ai_infra_guard": {"name": "AI-Infra-Guard", "surfaces": ["runtime"]}}
    metrics = score.score_all(corpus, {"results": [{**row, "predictions": stripped}]}, specs, services)
    level = metrics["tools"]["ai_infra_guard"]["value_level"]
    counts = {key: level["by_surface"]["runtime"][key] for key in ("tp", "fp", "fn")}
    assert counts == {"tp": 0, "fp": 2, "fn": 6}
    assert counts == {key: level["in_scope"][key] for key in ("tp", "fp", "fn")}
    assert "| 0% (0/2/6) |" in report.render(metrics, corpus, title="t")


# --- the run's freeze record and harness revision -------------------------------------------------


def _frozen_inputs(tmp_path: Path) -> tuple[list[str], Path, Path]:
    """A one-entity estate frozen under tmp_path; returns the score argv, FREEZE.json and runs.json."""
    estate = tmp_path / "artifacts"
    (estate / "endpoint").mkdir(parents=True)
    (estate / "endpoint" / "a.json").write_text('{"client": "cursor-anchor"}\n', encoding="utf-8")
    corpus = tmp_path / "corpus.json"
    entity = _entity("endpoint.cursor", "endpoint", "cursor-anchor", "ai-client:cursor")
    corpus.write_text(json.dumps({"schema": 1, "metadata": {}, "entities": [entity]}), encoding="utf-8")
    freeze = tmp_path / "FREEZE.json"
    assert cmd_freeze(corpus, estate, freeze) == 0
    runs = tmp_path / "runs.json"
    argv = ["score", "--corpus", str(corpus), "--estate", str(estate), "--freeze", str(freeze)]
    return [*argv, "--runs", str(runs), "--out", str(tmp_path / "metrics.json")], freeze, runs


def _write_run(runs: Path, freeze_path: Path, /, **fields: Any) -> None:
    row = {
        **_run({"fact": "ai-client:cursor", "text": "cursor-anchor", "surface": "endpoint"}),
        "tool": "shadowscan",
    }
    manifest: dict[str, Any] = {
        "started": "2026-10-12T00:00:00+00:00",
        "harness_commit": COMMIT,
        "harness_dirty": False,
        "freeze": {"sha256": sha256_file(freeze_path), "files": 2, "drift_after": []},
        "results": [row],
        "finished": "2026-10-12T00:00:01+00:00",
    }
    manifest.update(fields)
    runs.write_text(json.dumps(manifest), encoding="utf-8")


def _rendered(tmp_path: Path) -> str:
    out = tmp_path / "REPORT.md"
    corpus = str(tmp_path / "corpus.json")
    assert (
        main(["report", "--corpus", corpus, "--metrics", str(tmp_path / "metrics.json"), "--out", str(out)])
        == 0
    )
    return _words(out.read_text(encoding="utf-8"))


def test_holding_freeze_record_and_harness_revision_reach_the_metrics_and_report(tmp_path: Path) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    _write_run(runs, freeze)

    assert main(argv) == 0
    run = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))["run"]
    assert run["harness_commit"] == COMMIT and run["harness_dirty"] is False
    assert run["freeze"] == {"sha256": sha256_file(freeze), "files": 2, "drift_after": []}
    assert run[score.FREEZE_PROBLEMS] == []
    rendered = _rendered(tmp_path)
    assert (
        f"The harness ran from commit `{COMMIT}`, with no tracked file under `tools/` modified." in rendered
    )
    assert f"SHA-256 `{sha256_file(freeze)}` (2 files); no frozen file had changed" in rendered
    assert "the corpus and estate still matched it" in rendered


def test_run_that_drifted_is_refused_unless_allowed_and_then_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    drift = ["artifacts/endpoint/a.json"]
    _write_run(runs, freeze, freeze={"sha256": sha256_file(freeze), "files": 2, "drift_after": drift})

    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "the estate changed during the run (drifted files: 1)" in err
    assert "--allow-freeze-mismatch" in err
    assert not (tmp_path / "metrics.json").exists()

    assert main([*argv, "--allow-freeze-mismatch"]) == 0
    assert "note: scoring despite" in capsys.readouterr().err
    run = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))["run"]
    assert run["freeze"]["drift_after"] == drift
    assert run[score.FREEZE_PROBLEMS] == ["the estate changed during the run (drifted files: 1)"]
    rendered = _rendered(tmp_path)
    assert "**when it finished, frozen files had changed: 1**" in rendered
    assert "**Scored with `--allow-freeze-mismatch`, although the estate changed during the run" in rendered


def test_run_checked_against_another_freeze_manifest_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    _write_run(runs, freeze, freeze={"sha256": "0" * 64, "files": 2, "drift_after": []})

    assert main(argv) == 2
    assert "the freeze manifest is not the one the run was checked against" in capsys.readouterr().err
    assert not (tmp_path / "metrics.json").exists()


def test_corpus_changed_since_the_freeze_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    _write_run(runs, freeze)
    corpus = tmp_path / "corpus.json"
    corpus.write_text(corpus.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "the corpus and estate scored against differ from the freeze manifest (files: 1)" in err
    assert "is not the one the run was checked against" not in err


def test_missing_freeze_manifest_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    _write_run(runs, freeze)
    freeze.unlink()

    assert main(argv) == 2
    assert "cannot be read (FileNotFoundError)" in capsys.readouterr().err


@pytest.mark.parametrize(
    "fields",
    [
        {"freeze": None},
        {"freeze": {"sha256": "not-a-digest", "files": 2, "drift_after": []}},
        {"freeze": {"sha256": "0" * 64, "files": True, "drift_after": []}},
        {"freeze": {"sha256": "0" * 64, "files": 2, "drift_after": [3]}},
        {"harness_commit": "main"},
        {"harness_dirty": "no"},
    ],
    ids=["null-freeze", "bad-digest", "bool-files", "bad-drift", "branch-name", "string-dirty"],
)
def test_malformed_provenance_is_refused_even_when_mismatch_is_allowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fields: dict[str, Any]
) -> None:
    argv, freeze, runs = _frozen_inputs(tmp_path)
    _write_run(runs, freeze, **fields)

    assert main([*argv, "--allow-freeze-mismatch"]) == 2
    assert "record is malformed" in capsys.readouterr().err
    assert not (tmp_path / "metrics.json").exists()


def test_committed_run_report_says_it_recorded_no_provenance(committed: tuple[dict[str, Any], str]) -> None:
    metrics, rendered = committed
    assert not any(key in metrics["run"] for key in (*score.PROVENANCE_FIELDS, score.FREEZE_PROBLEMS))
    assert (
        "This run recorded no harness commit and no freeze digest: its runs.json predates those fields"
        in _words(rendered)
    )


@pytest.mark.parametrize(
    ("run", "shown", "hidden"),
    [
        (
            {"harness_commit": None, "harness_dirty": None},
            [
                "The harness commit could not be read when the run started; whether tracked files under "
                "`tools/` were modified is unknown. It recorded no freeze digest."
            ],
            [],
        ),
        (
            {"harness_commit": "main\n# injected", "harness_dirty": True, "freeze": "x"},
            [
                "is not a commit id and is not shown, with tracked files under `tools/` modified from it.",
                "Its freeze record is malformed and is not shown.",
                "do not record whether that freeze still held",
            ],
            ["injected"],
        ),
    ],
    ids=["unknown-revision", "edited-metrics"],
)
def test_report_shows_only_well_formed_provenance(
    run: dict[str, Any], shown: list[str], hidden: list[str]
) -> None:
    text = report._provenance(run)
    for sentence in shown:
        assert sentence in text
    for fragment in hidden:
        assert fragment not in text
