"""Unit tests for estate scoring and reporting (tools/shadowbench/estate/score.py, report.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.shadowbench.estate import report, score, taxonomy
from tools.shadowbench.estate.__main__ import main
from tools.shadowbench.estate.corpus import EstateCorpus, corpus_from_dict, load_corpus

ROOT = Path(__file__).resolve().parents[2]
TRACK = ROOT / "benchmarks" / "shadowbench" / "estate"
RESULTS = TRACK / "results" / "2026-10-11"

ENDPOINT = frozenset({"endpoint"})


def _entity(
    entity_id: str,
    surface: str,
    klass: str,
    unit: str,
    anchors: list[str],
    artifacts: list[str],
    expected: tuple[str, ...] = (),
    tolerated: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "id": entity_id,
        "surface": surface,
        "class": klass,
        "difficulty": "easy",
        "unit": unit,
        "expected": [{"fact": fact, "evidence": [artifacts[0]]} for fact in expected],
        "tolerated": list(tolerated),
        "anchors": anchors,
        "artifacts": artifacts,
    }


H1 = "home/h1/dana"
ENTITIES: list[dict[str, Any]] = [
    _entity(
        "code.repo-alpha",
        "code",
        "positive",
        "code:repo-alpha",
        ["repo-alpha"],
        ["code/repo-alpha/app.py"],
        expected=("framework:langgraph",),
    ),
    _entity("code.repo-beta", "code", "control", "code:repo-beta", ["repo-beta"], ["code/repo-beta/app.py"]),
    _entity(
        "endpoint.claude-code-h1",
        "endpoint",
        "positive",
        "home:h1",
        [".claude.json"],
        [f"{H1}/.claude.json"],
        expected=("ai-client:claude-code",),
        tolerated=("mcp:server",),
    ),
    _entity(
        "endpoint.cursor-h1",
        "endpoint",
        "positive",
        "home:h1",
        [".cursor/mcp.json"],
        [f"{H1}/.cursor/mcp.json"],
        expected=("ai-client:cursor",),
        tolerated=("mcp:server",),
    ),
    _entity(
        "endpoint.windsurf-h1",
        "endpoint",
        "positive",
        "home:h1",
        [".codeium/windsurf/mcp_config.json"],
        [f"{H1}/.codeium/windsurf/mcp_config.json"],
        expected=("ai-client:windsurf",),
        tolerated=("mcp:server",),
    ),
    # An MCP server configured in three of h1's clients: an estate-wide entity in h1's tree.
    _entity(
        "endpoint.mcp-freight",
        "endpoint",
        "positive",
        "estate",
        ["adatum-freight-mcp"],
        [f"{H1}/.claude.json", f"{H1}/.cursor/mcp.json", f"{H1}/.codeium/windsurf/mcp_config.json"],
        expected=("mcp:server",),
    ),
    _entity(
        "endpoint.claude-code-h2",
        "endpoint",
        "positive",
        "home:h2",
        ["marcus/.claude/settings.json"],
        ["home/h2/marcus/.claude/settings.json"],
        expected=("ai-client:claude-code",),
    ),
    _entity(
        "endpoint.ublock-h2",
        "endpoint",
        "control",
        "home:h2",
        ["ublock origin"],
        ["home/h2/marcus/ext/manifest.json"],
    ),
    _entity(
        "identity.app-aaaa",
        "identity",
        "positive",
        "estate",
        ["app-aaaa"],
        ["identity/apps.json"],
        expected=("oauth-app:generic",),
    ),
    _entity(
        "identity.app-bbbb",
        "identity",
        "positive",
        "estate",
        ["app-bbbb"],
        ["identity/apps.json"],
        expected=("oauth-app:generic",),
    ),
    _entity(
        "identity.gemini-exchange", "identity", "nearmiss", "estate", ["gemini-exch"], ["identity/apps.json"]
    ),
]
POSITIVES = sum(1 for item in ENTITIES if item["class"] == "positive")


def _corpus(entities: list[dict[str, Any]] | None = None) -> EstateCorpus:
    return corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities or ENTITIES})


def _pred(fact: str, text: str, surface: str | None = "endpoint") -> dict[str, Any]:
    prediction: dict[str, Any] = {"fact": fact, "text": text, "shadow": None}
    if surface is not None:
        prediction["surface"] = surface
    return prediction


def _row(
    unit: str,
    predictions: tuple[dict[str, Any], ...] = (),
    *,
    tool: str = "inv",
    status: str = "ok",
    exit_code: int = 0,
    ok: bool = True,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "unit": unit,
        "status": status,
        "seconds": 0.5,
        "predictions": list(predictions),
        "commands": [{"argv": ["inv"], "exit_code": exit_code, "ok": ok, "timed_out": False}],
        "error": None,
        "incomplete": False,
    }


def _score(rows: list[dict[str, Any]], surfaces: frozenset[str] = ENDPOINT) -> dict[str, Any]:
    return score.score_tool(_corpus(), "inv", surfaces, rows)


CLAUDE_H1 = _pred("ai-client:claude-code", f"claude_code <estate>/{H1}/.claude.json")


# --- value matching -------------------------------------------------------------------------------


def test_surplus_generic_is_neither_charged_nor_credited() -> None:
    counts = score.match_values({"ai-client:cursor", "ai-client:generic"}, frozenset({"ai-client:cursor"}))
    assert (counts.tp, counts.fp, counts.fn) == (1, 0, 0)


def test_generic_still_consumes_one_expected_fact_and_is_charged_off_category() -> None:
    counts = score.match_values({"ai-client:generic"}, frozenset({"ai-client:cursor", "mcp:server"}))
    assert (counts.tp, counts.fp, counts.fn) == (1, 0, 1)
    counts = score.match_values({"bot-app:generic"}, frozenset({"ai-client:cursor"}))
    assert (counts.tp, counts.fp, counts.fn) == (0, 1, 1)


# --- in-scope versus estate-wide entity metrics ----------------------------------------------------


def test_in_scope_entity_metrics_count_only_declared_surfaces() -> None:
    rows = [
        _row("code:repo-alpha", (_pred("framework:langgraph", "repo-alpha", "code"),)),
        _row("code:repo-beta"),
    ]
    result = _score(rows, frozenset({"code"}))
    entity = result["entity_level"]
    assert (entity["positives"], entity["positives_detected"]) == (1, 1)
    assert (entity["tp"], entity["fp"], entity["tn"], entity["fn"]) == (1, 0, 1, 0)
    assert entity["recall"] == 1.0
    estate = result["estate_wide"]
    assert (estate["positives_detected"], estate["positives"]) == (1, POSITIVES)


# --- completeness ---------------------------------------------------------------------------------


def test_failed_run_is_not_a_clean_negative() -> None:
    rows = [_row("home:h1", (CLAUDE_H1,)), _row("home:h2", status="failed", exit_code=2, ok=False)]
    result = _score(rows)
    entity = result["entity_level"]
    assert entity["tn"] == 0
    assert entity["negatives_unscored"] == 1 and entity["positives_unscored"] == 1
    assert result["per_entity"]["endpoint.ublock-h2"]["unscored"] is True
    assert result["complete"] is False
    assert result["incomplete_units"] == [{"unit": "home:h2", "reason": "status failed"}]


def test_command_exit_the_adapter_does_not_accept_makes_the_run_incomplete() -> None:
    rows = [_row("home:h1", (CLAUDE_H1,)), _row("home:h2", exit_code=2, ok=False)]
    result = _score(rows)
    assert result["entity_level"]["tn"] == 0
    assert result["per_entity"]["endpoint.ublock-h2"]["unscored"] is True
    assert "exit code 2" in result["incomplete_units"][0]["reason"]


def test_findings_from_an_incomplete_run_are_not_credited() -> None:
    rows = [_row("home:h1", (CLAUDE_H1,), status="timeout"), _row("home:h2")]
    result = _score(rows)
    claude = result["per_entity"]["endpoint.claude-code-h1"]
    assert claude["detected"] is False and claude["unscored"] is True
    assert (claude["tp"], claude["fn"]) == (0, 1)
    # The estate-wide MCP server entity has an artifact in h1's tree, so the timeout reaches it too.
    assert result["per_entity"]["endpoint.mcp-freight"]["unscored"] is True
    assert result["entity_level"]["positives_detected"] == 0
    assert result["entity_level"]["tn"] == 1


def test_tool_without_runs_is_incomplete_everywhere() -> None:
    result = _score([])
    assert result["entity_level"]["tn"] == 0
    assert result["complete"] is False
    assert result["entity_level"]["positives_unscored"] == result["entity_level"]["positives"]


def test_labeled_unit_without_a_run_is_missing() -> None:
    result = _score([_row("home:h1", (CLAUDE_H1,))])
    assert result["entity_level"]["tn"] == 0
    assert result["per_entity"]["endpoint.claude-code-h1"]["detected"] is True
    assert result["incomplete_units"] == [{"unit": "home:h2", "reason": score.MISSING_RUN}]


def test_nonzero_exit_the_adapter_accepts_is_counted_not_failed() -> None:
    rows = [_row("home:h1", (CLAUDE_H1,)), _row("home:h2", exit_code=1)]
    result = _score(rows)
    assert result["complete"] is True
    assert result["commands"] == {"total": 2, "nonzero_exit_accepted": 1}
    assert result["entity_level"]["tn"] == 1


def test_report_shows_status_counts_and_marks_incomplete_tools() -> None:
    corpus = _corpus()
    manifest = {"results": [_row("home:h1", (CLAUDE_H1,)), _row("home:h2", status="failed", ok=False)]}
    metrics = score.score_all(corpus, manifest, {"inv": {"name": "Inventory", "surfaces": ["endpoint"]}})
    text = report.render(metrics, corpus, title="t")
    assert "| **incomplete** (1 failed, 1 ok) |" in text
    assert "home:h2 (status failed)" in text
    assert "| endpoint.ublock-h2 | endpoint | control | unscored |" in text
    assert "Unscored in-scope entities" in text


# --- attribution ----------------------------------------------------------------------------------


def test_expected_fact_beats_a_longer_anchor_of_another_entity() -> None:
    """vet's Claude Code row names the configured MCP server; the client entity owns it."""
    prediction = _pred("ai-client:claude-code", f"claude_code adatum-freight-mcp <estate>/{H1}/.claude.json")
    result = _score([_row("home:h1", (prediction,)), _row("home:h2")])
    assert result["per_entity"]["endpoint.claude-code-h1"]["detected"] is True
    assert result["per_entity"]["endpoint.mcp-freight"]["fp"] == 0
    assert result["value_level"]["in_scope"]["fp"] == 0


def test_server_row_in_a_client_config_goes_to_the_server_entity() -> None:
    prediction = _pred(
        "mcp:server",
        f"adatum-freight-mcp <estate>/{H1}/.codeium/windsurf/mcp_config.json /opt/adatum-freight-mcp/bin/run",
    )
    result = _score([_row("home:h1", (prediction,)), _row("home:h2")])
    assert result["per_entity"]["endpoint.mcp-freight"]["detected"] is True


def test_attribution_stays_on_the_prediction_surface() -> None:
    prediction = {
        **_pred("mcp-client-config:cursor", "repo-alpha/.cursor/mcp.json", "code"),
        "unit": "estate",
    }
    result = score.attribute(_corpus(), [prediction])
    assert result.entity_predictions["code.repo-alpha"] == [prediction]
    assert result.entity_predictions["endpoint.cursor-h1"] == []


def test_unit_bound_run_does_not_reach_another_units_entities() -> None:
    prediction = _pred("ai-client:claude-code", "claude <estate>/home/h2/marcus/.claude.json")
    result = _score([_row("home:h1"), _row("home:h2", (prediction,))])
    assert result["per_entity"]["endpoint.claude-code-h2"]["detected"] is True
    assert result["per_entity"]["endpoint.claude-code-h1"]["detected"] is False


def test_ambiguous_attribution_is_counted_and_independent_of_corpus_order() -> None:
    prediction = {**_pred("oauth-app:generic", "grant app-bbbb app-aaaa", "identity"), "unit": "estate"}
    for entities in (list(reversed(ENTITIES)), ENTITIES):
        result = score.attribute(_corpus(entities), [prediction])
        assert result.entity_predictions["identity.app-aaaa"] == [prediction]
        assert result.entity_predictions["identity.app-bbbb"] == []
        assert [item["candidates"] for item in result.ambiguous] == [
            ["identity.app-aaaa", "identity.app-bbbb"]
        ]
    rows = [_row("estate", (prediction,))]
    scored = _score(rows, frozenset({"identity"}))
    assert scored["predictions"]["ambiguous"] == 1
    text = report.render(
        score.score_all(_corpus(), {"results": rows}, {"inv": {"name": "Inv", "surfaces": ["identity"]}}),
        _corpus(),
        title="t",
    )
    assert "Ambiguous attributions" in text and "→ identity.app-aaaa" in text


# --- scope of predictions -------------------------------------------------------------------------


def test_in_scope_prediction_is_never_silently_dropped() -> None:
    """A code-surface prediction carrying an endpoint entity's anchor is charged, not lost."""
    prediction = _pred("mcp-client-config:cursor", f"<estate>/{H1}/.cursor/mcp.json", "code")
    result = _score([_row("estate", (prediction,))], frozenset({"code"}))
    assert result["value_level"]["in_scope"]["fp"] == 1
    assert result["predictions"]["unattributed"] == 1


def test_prediction_outside_declared_surfaces_counts_estate_wide_only() -> None:
    prediction = _pred("ai-client:cursor", f"<estate>/{H1}/.cursor/mcp.json")
    result = _score([_row("estate", (prediction,))], frozenset({"code"}))
    assert result["predictions"]["out_of_scope"] == 1
    assert result["value_level"]["in_scope"]["tp"] == 0 and result["value_level"]["in_scope"]["fp"] == 0
    assert result["value_level"]["all"]["tp"] == 1
    assert result["estate_wide"]["positives_detected"] == 1


def test_prediction_without_a_surface_is_placed_by_its_category() -> None:
    prediction = _pred("ai-client:cursor", f"<estate>/{H1}/.cursor/mcp.json", surface=None)
    result = _score([_row("home:h1", (prediction,)), _row("home:h2")])
    assert result["per_entity"]["endpoint.cursor-h1"]["detected"] is True
    assert result["predictions"]["out_of_scope"] == 0


def test_category_surfaces_cover_every_category_and_the_committed_corpus() -> None:
    assert set(taxonomy.CATEGORY_SURFACES) == set(taxonomy.CATEGORIES)
    assert all(surfaces <= set(taxonomy.SURFACES) for surfaces in taxonomy.CATEGORY_SURFACES.values())
    corpus = load_corpus(TRACK / "corpus.json")
    for entity in corpus.entities:
        for fact in (*entity.expected_facts, *entity.tolerated):
            assert entity.surface in taxonomy.category_surfaces(taxonomy.category(fact)), (entity.id, fact)


# --- the committed run ----------------------------------------------------------------------------


def _committed_runs() -> list[dict[str, Any]]:
    manifest = json.loads((RESULTS / "runs.json").read_text(encoding="utf-8"))
    return list(manifest["results"])


def test_committed_run_keeps_vet_client_rows_with_their_clients() -> None:
    """vet's Claude Code and Cursor rows name adatum-freight-mcp; they were charged to it as FPs."""
    corpus = load_corpus(TRACK / "corpus.json")
    result = score.score_tool(corpus, "vet", frozenset({"code", "endpoint"}), _committed_runs())
    assert result["per_entity"]["endpoint.mcp-adatum-freight"]["fp"] == 0
    assert result["value_level"]["in_scope"]["fp"] == 0
    assert result["entity_level"]["positives"] == len(
        [e for e in corpus.by_class("positive") if e.surface in {"code", "endpoint"}]
    )


def test_committed_metrics_and_report_match_a_rescore(tmp_path: Path) -> None:
    """The published metrics.json and REPORT.md are what the current scorer makes of runs.json."""
    corpus = str(TRACK / "corpus.json")
    metrics = tmp_path / "metrics.json"
    rendered = tmp_path / "REPORT.md"
    assert (
        main(["score", "--corpus", corpus, "--runs", str(RESULTS / "runs.json"), "--out", str(metrics)]) == 0
    )
    assert json.loads(metrics.read_text(encoding="utf-8")) == json.loads(
        (RESULTS / "metrics.json").read_text(encoding="utf-8")
    )
    assert main(["report", "--corpus", corpus, "--metrics", str(metrics), "--out", str(rendered)]) == 0
    assert rendered.read_text(encoding="utf-8") == (RESULTS / "REPORT.md").read_text(encoding="utf-8")
