"""Regression tests for the estate fixes after the second review round
(tools/shadowbench/estate/score.py, report.py, __main__.py and the Snyk Agent Scan, Numbat,
vet and AI-Infra-Guard adapters).

- The live-sim (`sim`) run counted as reaching every entity, so AI-Infra-Guard earned true
  negatives for runtime controls and near-misses no mock service stood in for.
- A report of the wrong shape (an error object, rows without the agent fields) normalized to a
  complete empty inventory, which earns true negatives.
- The scorer and the report said a flag on a negative is never handed to a positive; the
  anchor-length and entity-id tie-breaks can do exactly that.
- `score` without a services file only printed a note while it charged every scan target as a
  false positive, and a scan target of any text reached the metrics and the report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.estate import report, score
from tools.shadowbench.estate.__main__ import main
from tools.shadowbench.estate.adapters import ToolConfig
from tools.shadowbench.estate.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.shadowbench.estate.adapters.code_wrappers import VetEstateAdapter
from tools.shadowbench.estate.adapters.mcp_scan import McpScanAdapter
from tools.shadowbench.estate.adapters.numbat import NumbatAdapter
from tools.shadowbench.estate.corpus import EstateCorpus, corpus_from_dict, load_corpus

ROOT = Path(__file__).resolve().parents[2]
TRACK = ROOT / "benchmarks" / "shadowbench" / "estate"
RESULTS = TRACK / "results" / "2026-10-11"
RUNTIME = frozenset({"runtime"})

OLLAMA_ANCHOR = "dev-laptop-02:marcus:ollama"
VLLM_ANCHOR = "build-runner-3:ci:vllm"
AIDER_ANCHOR = "dev-laptop-02:marcus:aider"
SERVICES = {"ollama-dev-laptop-02": OLLAMA_ANCHOR, "vllm-build-runner-3": VLLM_ANCHOR}


def _entity(
    entity_id: str,
    klass: str,
    anchor: str,
    fact: str | None = None,
    *,
    surface: str = "runtime",
    unit: str = "estate",
) -> dict[str, Any]:
    artifact = (
        "runtime/processes.jsonl" if unit == "estate" else f"home/{unit.partition(':')[2]}/u/.claude.json"
    )
    return {
        "id": entity_id,
        "surface": surface,
        "class": klass,
        "difficulty": "easy",
        "unit": unit,
        "expected": [{"fact": fact, "evidence": [artifact]}] if fact else [],
        "anchors": [anchor],
        "artifacts": [artifact],
    }


ENTITIES = [
    _entity("runtime.ollama-marcus", "positive", OLLAMA_ANCHOR, "agent-process:ollama"),
    _entity("runtime.vllm-runner", "positive", VLLM_ANCHOR, "agent-process:vllm"),
    # Runtime entities no services.json service stands in for: the live-sim stages nothing for them.
    _entity("runtime.aider-marcus", "positive", AIDER_ANCHOR, "agent-process:generic"),
    _entity("runtime.nginx-control", "control", "build-runner-3:root:nginx"),
    _entity("runtime.claudette-nearmiss", "nearmiss", "dev-laptop-01:root:claudette-backup"),
]


def _corpus(entities: list[dict[str, Any]] | None = None) -> EstateCorpus:
    return corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities or ENTITIES})


def _pred(fact: str, text: str) -> dict[str, Any]:
    return {"fact": fact, "text": text, "surface": "runtime", "shadow": None}


OLLAMA = _pred("agent-process:ollama", "http://127.0.0.1:11434 ollama:0.3.9")
VLLM = _pred("agent-process:vllm", "http://127.0.0.1:8000 openai-compatible vllm:0.6.3")


def _row(
    predictions: list[dict[str, Any]],
    targets: Any = None,
    *,
    record: bool = True,
    unit: str = score.SIM_UNIT,
    status: str = "ok",
) -> dict[str, Any]:
    return {
        "tool": "ai_infra_guard",
        "unit": unit,
        "status": status,
        "seconds": 1.0,
        "predictions": predictions,
        "raw_count": len(predictions),
        "commands": [{"argv": ["simhost"], "exit_code": 0, "ok": True, "timed_out": False}],
        "error": None,
        "detail": {score.SCAN_TARGETS: targets} if record else {},
        "incomplete": False,
    }


def _score(
    rows: list[dict[str, Any]],
    services: dict[str, str] | None = None,
    surfaces: frozenset[str] = RUNTIME,
    corpus: EstateCorpus | None = None,
) -> dict[str, Any]:
    return score.score_tool(
        corpus or _corpus(), "ai_infra_guard", surfaces, rows, SERVICES if services is None else services
    )


def _metrics(result: dict[str, Any], corpus: EstateCorpus) -> dict[str, Any]:
    return {
        "corpus": {
            "entities": len(corpus.entities),
            "positive": len(corpus.by_class("positive")),
            "control": len(corpus.by_class("control")),
            "nearmiss": len(corpus.by_class("nearmiss")),
            "registered": 0,
            "expected_facts": sum(len(e.expected) for e in corpus.entities),
            "expected_by_surface": {},
        },
        "run": {},
        "tools": {
            "ai_infra_guard": {"name": "AI-Infra-Guard", "version": "t", "surfaces": ["runtime"], **result}
        },
    }


# --- E1: the live-sim run reaches only what services.json mirrors ---------------------------------


def test_live_sim_run_earns_no_true_negative_for_entities_it_does_not_stage() -> None:
    result = _score([_row([OLLAMA, VLLM], ["ollama-dev-laptop-02", "vllm-build-runner-3"])])

    entity = result["entity_level"]
    assert entity["positives_detected"] == 2 and entity["fn"] == 1
    assert entity["tn"] == 0
    assert entity["negatives_not_reached"] == 2 and entity["positives_not_reached"] == 1
    reached = {entity_id for entity_id, row in result["per_entity"].items() if row["reached"]}
    assert reached == {"runtime.ollama-marcus", "runtime.vllm-runner"}
    assert result["complete"] is True

    rendered = report.render(_metrics(result, _corpus()), _corpus(), title="t")
    assert "| runtime.nginx-control | runtime | control | not reached |" in rendered
    assert "| runtime.claudette-nearmiss | runtime | nearmiss | not reached |" in rendered
    assert "or a runtime entity no live-sim mock service stands in for, is not reached" in rendered


def test_live_sim_prediction_naming_an_unstaged_entity_is_not_attributed_to_it() -> None:
    """The live-sim cannot have seen the aider process, so text naming it does not credit it."""
    named = _pred("agent-process:generic", f"http://127.0.0.1:11434 {AIDER_ANCHOR}")
    result = _score([_row([named], record=False)])

    assert result["per_entity"]["runtime.aider-marcus"]["detected"] is False
    assert result["predictions"]["unattributed"] == 1
    assert result["value_level"]["in_scope"]["fp"] == 1


def test_live_sim_run_without_services_reaches_nothing() -> None:
    texted = _pred("agent-process:ollama", f"http://127.0.0.1:11434 ollama:0.3.9 {OLLAMA_ANCHOR}")
    result = _score([_row([texted], record=False)], services={})

    assert result["entity_level"]["positives_detected"] == 0 and result["entity_level"]["tn"] == 0
    assert result["entity_level"]["positives_not_reached"] == 3
    assert result["entity_level"]["negatives_not_reached"] == 2
    assert result["predictions"]["unattributed"] == 1


def test_failed_live_sim_run_leaves_only_the_mirrored_entities_unscored() -> None:
    result = _score([_row([OLLAMA], ["ollama-dev-laptop-02"], status="failed")])

    assert result["complete"] is False
    unscored = {entity_id for entity_id, row in result["per_entity"].items() if row["unscored"]}
    assert unscored == {"runtime.ollama-marcus", "runtime.vllm-runner"}
    assert result["entity_level"]["tn"] == 0 and result["entity_level"]["negatives_not_reached"] == 2


def test_reach_of_each_kind_of_unit() -> None:
    corpus = _corpus()
    ollama, nginx = corpus.get("runtime.ollama-marcus"), corpus.get("runtime.nginx-control")
    assert score.reaches(score.ESTATE_UNIT, nginx)
    assert score.reaches(score.SIM_UNIT, ollama, SERVICES)
    assert not score.reaches(score.SIM_UNIT, nginx, SERVICES)
    assert not score.reaches(score.SIM_UNIT, ollama)
    # A unit that is neither the estate, the live-sim nor a code or home unit reaches nothing.
    for unit in ("bogus", "code:", "home:", "sim:x", "Estate"):
        assert not score.reaches(unit, ollama, SERVICES), unit


def test_live_sim_row_does_not_stand_in_for_missing_home_runs() -> None:
    """A home unit on the tool's surfaces with no run of its own is missing, sim row or not."""
    entities = [
        *ENTITIES,
        _entity(
            "endpoint.claude-h1",
            "positive",
            "h1-claude",
            "ai-client:claude-code",
            surface="endpoint",
            unit="home:h1",
        ),
    ]
    corpus = _corpus(entities)
    result = _score(
        [_row([OLLAMA], ["ollama-dev-laptop-02"])], surfaces=frozenset({"runtime", "endpoint"}), corpus=corpus
    )

    assert result["incomplete_units"] == [{"unit": "home:h1", "reason": score.MISSING_RUN}]
    assert result["per_entity"]["endpoint.claude-h1"]["unscored"] is True


def test_committed_live_sim_run_earns_no_true_negative() -> None:
    corpus = load_corpus(TRACK / "corpus.json")
    services = score.load_services(TRACK / "artifacts" / "services" / "services.json")
    rows = json.loads((RESULTS / "runs.json").read_text(encoding="utf-8"))["results"]
    result = score.score_tool(corpus, "ai_infra_guard", RUNTIME, rows, services)

    entity = result["entity_level"]
    assert (entity["tp"], entity["fp"], entity["tn"], entity["fn"]) == (2, 0, 0, 4)
    assert entity["negatives_not_reached"] == 4 and entity["positives_not_reached"] == 4
    reached = {entity_id for entity_id, row in result["per_entity"].items() if row["reached"]}
    assert reached == {"runtime.ollama-serve-marcus", "runtime.vllm-build-runner"}


def test_ai_infra_guard_runs_the_live_sim_unit(tmp_path: Path) -> None:
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "services.json").write_text('{"services": []}', encoding="utf-8")
    assert AiInfraGuardAdapter().units(ToolConfig({"tools": {}}), tmp_path, _corpus()) == [score.SIM_UNIT]


# --- E2: a report of the wrong shape is an error, not an empty inventory --------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"error": "Traceback: boom"}',
        '{"error": {"message": "could not parse file", "is_failure": true}}',
        '{"/home/u/.cursor/mcp.json": {"path": "/home/u/.cursor/mcp.json", "servers": null}}',
        '{"a": 1, "b": [2], "c": null}',
        '{"/p": {"client": "", "servers": "x"}}',
        '{"/p": {"client": "cursor", "servers": "x"}}',
        '{"/p": {"client": null, "servers": null}}',
    ],
    ids=[
        "error-string",
        "error-object",
        "servers-null-without-client",
        "scalars",
        "blank-client",
        "client-with-bad-servers",
        "null-client-no-servers",
    ],
)
def test_mcp_scan_report_without_a_client_record_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "inspect.json").write_text(text, encoding="utf-8")

    normalized = McpScanAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == "inspect.json holds no client record"
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        ("{}", []),
        ('{"/p": {"path": "/p", "servers": []}}', []),
        ('{"/p": {"client": "cursor", "servers": null}, "error": "partial"}', ["ai-client:cursor"]),
        (
            '{"/p": {"client": "windsurf", "servers": [{"name": "github", "server": {"command": "npx"}}]}}',
            ["ai-client:windsurf", "mcp:server"],
        ),
        # A null client names no client: it used to read as a client called "None".
        (
            '{"/p": {"client": null, "servers": [{"name": "github", "server": {"command": "npx"}}]},'
            ' "/q": {"client": "cursor", "servers": {}}}',
            ["mcp:server", "ai-client:cursor"],
        ),
    ],
    ids=["empty", "servers-list", "client-beside-junk", "client-and-server", "null-client"],
)
def test_mcp_scan_report_with_client_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "inspect.json").write_text(text, encoding="utf-8")

    normalized = McpScanAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


@pytest.mark.parametrize(
    "text",
    [
        '[{"error": "Traceback: boom"}]',
        '[{"name": "Cursor", "present": true}]',
        '[{"agent": "Cursor"}]',
        '[{"agent": "", "present": true}]',
        '[1, "two", null]',
    ],
    ids=["error-object", "no-agent-field", "no-presence-field", "blank-agent", "non-records"],
)
def test_numbat_report_without_an_agent_record_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "agents.json").write_text(text, encoding="utf-8")

    normalized = NumbatAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == "agents.json holds no agent record"
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        ("[]", []),
        ('[{"agent": "Cursor", "present": false}]', []),
        ('[{"agent": "Cursor", "detected": true}, {"error": "partial"}]', ["ai-client:cursor"]),
        # Rows without an agent name are skipped, not read as a nameless generic client.
        (
            '[{"agent": "Cursor", "present": true}, {"present": true}, {"agent": 5, "detected": true}]',
            ["ai-client:cursor"],
        ),
    ],
    ids=["empty", "absent-agent", "agent-beside-junk", "nameless-rows-beside-agent"],
)
def test_numbat_report_with_agent_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "agents.json").write_text(text, encoding="utf-8")

    normalized = NumbatAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ('{"error": "Traceback: boom"}', "ai.json is not a list"),
        ('{"App": "claude_code", "Name": "github"}', "ai.json is not a list"),
        ("42", "ai.json is not a list"),
        ('"no tools found"', "ai.json is not a list"),
        ('[{"error": "Traceback: boom"}]', "ai.json holds no vet record"),
        ('[{"App": "", "Name": ""}]', "ai.json holds no vet record"),
        ('[{"MCPServer": {}}]', "ai.json holds no vet record"),
        ("[1, null]", "ai.json holds no vet record"),
    ],
    ids=[
        "error-object",
        "single-object",
        "number",
        "string",
        "error-row",
        "blank-names",
        "empty-server",
        "non-records",
    ],
)
def test_vet_home_report_of_the_wrong_shape_is_an_error(tmp_path: Path, text: str, error: str) -> None:
    (tmp_path / "ai.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == error
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        # The code-surface vet adapter records that vet writes `null` or `[]` when it finds nothing.
        ("null", []),
        ("[]", []),
        (
            '[{"App": "claude_code", "Name": "github", "ConfigPath": "/h/.claude.json",'
            ' "MCPServer": {"Command": "npx"}}, {"error": "partial"}]',
            ["mcp:server", "ai-client:claude-code"],
        ),
        # Items that are not records are skipped, not read as a client named "5".
        (
            '[{"App": "claude_code", "Name": "github", "ConfigPath": "/h/.claude.json"}, {"App": 5},'
            ' {"Name": ["x"]}]',
            ["ai-client:claude-code"],
        ),
    ],
    ids=["null", "empty", "record-beside-junk", "non-records-beside-record"],
)
def test_vet_home_report_with_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "ai.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ('{"error": "api down"}', "vet.json is not a list"),
        ('{"status": "failed", "items": []}', "vet.json is not a list"),
        ('"oops"', "vet.json is not a list"),
        ("42", "vet.json is not a list"),
        ('[{"error": "Traceback: boom"}]', "vet.json holds no vet record"),
        ("[1, null]", "vet.json holds no vet record"),
    ],
    ids=["error-object", "status-object", "string", "number", "error-row", "non-records"],
)
def test_vet_code_report_of_the_wrong_shape_is_an_error(tmp_path: Path, text: str, error: str) -> None:
    """On a code unit an error report is an adapter error, not an empty, complete inventory."""
    (tmp_path / "vet.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("code:repo-x", tmp_path)

    assert normalized.error == error


@pytest.mark.parametrize(
    "text", ["[]", "[ ]", "[\n]", " [\n  ]\n"], ids=["compact", "spaced", "newline", "indented"]
)
def test_vet_empty_report_reads_as_nothing_found_regardless_of_whitespace(tmp_path: Path, text: str) -> None:
    """A decoded empty list is a successful empty inventory however vet formats it."""
    (tmp_path / "vet.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("code:repo-x", tmp_path)

    assert normalized.error is None
    assert list(normalized.predictions) == []
    assert normalized.predictions == []


def test_vet_code_report_unparseable_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "vet.json").write_text('[{"Name": "fs"', encoding="utf-8")

    normalized = VetEstateAdapter().normalize("code:repo-x", tmp_path)

    assert normalized.error is not None
    assert normalized.error.startswith("vet.json")


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        (None, []),
        ("", []),
        ("null", []),
        ("[]", []),
        (
            '[{"Name": "fs", "MCPServer": {"Transport": "stdio"}, "ConfigPath": "/r/.vscode/mcp.json"},'
            ' {"error": "partial"}]',
            ["mcp-client-config:vscode"],
        ),
    ],
    ids=["missing", "empty", "null", "empty-list", "record-beside-junk"],
)
def test_vet_code_report_nothing_found_or_records_normalizes(
    tmp_path: Path, text: str | None, facts: list[str]
) -> None:
    if text is not None:
        (tmp_path / "vet.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("code:repo-x", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


# --- E3: the tie-breaks can hand a flag on a negative to a positive --------------------------------


def test_flag_matching_a_negative_and_a_positive_can_go_to_the_positive() -> None:
    corpus = load_corpus(TRACK / "corpus.json")
    prediction = {
        "fact": "ai-service-contact:gemini",
        "text": "10.31.4.50 192.168.7.30",
        "surface": "network",
        "unit": score.ESTATE_UNIT,
    }

    result = score.attribute(corpus, [prediction])

    assert result.entity_predictions["network.gemini-generic-dns"] == [prediction]
    assert result.entity_predictions["network.gemini-crypto-exchange"] == []
    (match,) = result.ambiguous
    assert match["rule"] == score.RULE_ANCHOR
    assert match["candidates"] == ["network.gemini-crypto-exchange", "network.gemini-generic-dns"]


def test_scorer_and_report_describe_the_tie_breaks_exactly() -> None:
    assert score.__doc__ is not None
    docstring = " ".join(score.__doc__.split())
    assert "never handed to a positive" not in docstring
    assert "can still hand the flag to a positive" in docstring
    rendered = report.render(_metrics(_score([_row([], [])]), _corpus()), _corpus(), title="t")
    assert "never handed to a positive" not in rendered
    assert (
        "so a flag on a negative can still go to a positive with a longer anchor or an earlier id" in rendered
    )
    assert "which is always so when a negative is among the candidates" in rendered


# --- E4: scoring needs services.json, and scan targets are plain ids -------------------------------


def _write_inputs(tmp_path: Path, rows: list[dict[str, Any]], services: str | None) -> list[str]:
    estate = tmp_path / "estate"
    (estate / "services").mkdir(parents=True)
    if services is not None:
        (estate / "services" / "services.json").write_text(services, encoding="utf-8")
    (tmp_path / "corpus.json").write_text(
        json.dumps({"schema": 1, "metadata": {}, "entities": ENTITIES}), encoding="utf-8"
    )
    (tmp_path / "runs.json").write_text(json.dumps({"results": rows}), encoding="utf-8")
    return [
        "score",
        "--corpus",
        str(tmp_path / "corpus.json"),
        "--estate",
        str(estate),
        "--runs",
        str(tmp_path / "runs.json"),
        "--out",
        str(tmp_path / "metrics.json"),
    ]


@pytest.mark.parametrize("services", [None, '{"services": []}'], ids=["missing", "empty"])
@pytest.mark.parametrize(
    "row",
    [
        _row([OLLAMA], ["ollama-dev-laptop-02"]),
        _row([OLLAMA], record=False),
        _row([OLLAMA], [None], unit="estate"),
    ],
    ids=["sim-with-targets", "sim-without-targets", "targets-on-another-unit"],
)
def test_score_refuses_runs_that_need_services_without_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], services: str | None, row: dict[str, Any]
) -> None:
    argv = _write_inputs(tmp_path, [row], services)

    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "is missing or lists no service" in err
    assert f"'ai_infra_guard' on '{row['unit']}'" in err
    assert "--allow-missing-services" in err
    assert not (tmp_path / "metrics.json").exists()

    assert main([*argv, "--allow-missing-services"]) == 0
    assert "note: no services in" in capsys.readouterr().err
    scored = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))["tools"]["ai_infra_guard"]
    assert scored["entity_level"]["positives_detected"] == 0
    if row["unit"] == score.SIM_UNIT:
        assert scored["entity_level"]["tn"] == 0 and scored["entity_level"]["negatives_not_reached"] == 2


def test_score_without_services_is_fine_for_runs_that_do_not_need_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    row = {**_row([], record=False, unit="estate"), "tool": "shadowscan"}
    argv = _write_inputs(tmp_path, [row], None)

    assert main(argv) == 0
    assert capsys.readouterr().err == ""


def test_score_with_services_attributes_the_targets(tmp_path: Path) -> None:
    services = (TRACK / "artifacts" / "services" / "services.json").read_text(encoding="utf-8")
    argv = _write_inputs(
        tmp_path, [_row([OLLAMA, VLLM], ["ollama-dev-laptop-02", "vllm-build-runner-3"])], services
    )

    assert main(argv) == 0
    scored = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))["tools"]["ai_infra_guard"]
    assert scored["predictions"]["harness_attributed"] == 2 and scored["entity_level"]["tn"] == 0


@pytest.mark.parametrize(
    "target",
    [
        "ollama-dev-laptop-02\n## injected heading",
        "ollama-dev-laptop-02\r",
        "svc`x",
        "svc one",
        "svc|x",
        "-leading-dash",
        "x" * 161,
        "café",
        score.NO_TARGET,
    ],
    ids=[
        "newline",
        "carriage-return",
        "backtick",
        "space",
        "pipe",
        "leading-dash",
        "too-long",
        "non-ascii",
        "marker",
    ],
)
def test_scan_target_that_is_not_a_plain_id_makes_the_record_malformed(target: str) -> None:
    row = _row([OLLAMA, VLLM], ["ollama-dev-laptop-02", target])

    assert score.incomplete_reason(row) == score.MALFORMED_TARGETS
    result = _score([row])
    assert result["complete"] is False
    assert [item[score.SCAN_TARGET] for item in result["unattributed"]] == [score.NO_TARGET] * 2
    rendered = report.render(_metrics(result, _corpus()), _corpus(), title="t")
    if target != score.NO_TARGET:
        assert target not in rendered
    assert "## injected" not in rendered


@pytest.mark.parametrize("target", ["http://127.0.0.1:9999", "ollama-dev-laptop-02", "a" * 160, "svc_1.v2"])
def test_plain_scan_targets_are_accepted(target: str) -> None:
    assert score.plain_scan_target(target)
    assert score.incomplete_reason(_row([OLLAMA], [target])) is None


def test_report_does_not_show_a_scan_target_that_is_not_plain() -> None:
    """metrics.json is an input to `report`; a target edited into it is not rendered."""
    result = _score([_row([OLLAMA], ["not-a-service"])])
    result["unattributed"][0][score.SCAN_TARGET] = "x`\n# injected"

    rendered = report.render(_metrics(result, _corpus()), _corpus(), title="t")

    assert "# injected" not in rendered
    assert "(its scan target is not a plain id and is not shown; it maps to no estate host)" in rendered


# --- E4: AI-Infra-Guard normalize branches that had no test ---------------------------------------


def _staged(out_dir: Path, offset: object) -> None:
    payload = {
        "services": [
            {"id": "ollama-dev-laptop-02", "kind": "ollama", "port": 11434, "anchor": OLLAMA_ANCHOR},
            {"id": "vllm-build-runner-3", "kind": "vllm", "port": 8000, "anchor": VLLM_ANCHOR},
        ],
        "port_offset": offset,
    }
    (out_dir / "services.json").write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.parametrize("offset", ["100", 1.5, True, None, [0]])
def test_non_integer_port_offset_in_the_staged_services_file_fails_closed(
    tmp_path: Path, offset: object
) -> None:
    _staged(tmp_path, offset)
    (tmp_path / "scan.txt").write_text("http://127.0.0.1:11434 [200] [ollama:0.3.9]\n", encoding="utf-8")

    normalized = AiInfraGuardAdapter().normalize(score.SIM_UNIT, tmp_path)

    assert normalized.error == (
        "cannot map scanned targets to staged services: services.json: port_offset must be an integer"
    )
    assert normalized.detail[score.SCAN_TARGETS] == ["http://127.0.0.1:11434"]
    assert "port_offset" not in normalized.detail
    # The runner records the error, which makes the run incomplete.
    assert score.incomplete_reason({**_row([OLLAMA], ["http://127.0.0.1:11434"]), "error": normalized.error})


def test_scan_with_target_lines_but_no_fingerprint_is_a_complete_empty_result(tmp_path: Path) -> None:
    """Every target answered and none was fingerprinted: nothing to map, so no services file is read."""
    (tmp_path / "scan.txt").write_text(
        "http://127.0.0.1:11434 [200]\nhttp://127.0.0.1:8000 [404] []\n", encoding="utf-8"
    )
    (tmp_path / "services.json").write_text("{", encoding="utf-8")

    normalized = AiInfraGuardAdapter().normalize(score.SIM_UNIT, tmp_path)

    assert normalized.error is None and normalized.raw_count == 2
    assert normalized.predictions == []
    assert score.SCAN_TARGETS not in normalized.detail and "port_offset" not in normalized.detail
    # Scored, the mirrored positives are missed and nothing earns a true negative.
    result = _score([_row([], record=False)])
    assert result["complete"] is True
    assert result["entity_level"]["positives_detected"] == 0 and result["entity_level"]["tn"] == 0
