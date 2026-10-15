"""Malformed live definitions and continuations cannot authorize complete negative scans."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.cli import _exit_code
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.lowcode import automation
from shadowscan.engine import Engine

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "lowcode" / "collection_boundaries.json").read_text()
)
VALID_MAKE = {"flow": [{"module": "openai-gpt-3:CreateCompletion"}]}
VALID_ZAP = {"id": "observed", "title": "Triage", "steps": ["Gmail", "ChatGPT"]}


def _scan(index, connector, **config):
    return Engine(ScanConfig(connectors=[ConnectorSpec(connector, config=config)]), index).run()


def _make_api(monkeypatch, blueprint, *, include_valid=False):
    scenarios = [{"id": "candidate", "name": "Routine backup"}]
    if include_valid:
        scenarios.append({"id": "observed", "name": "Ticket triage"})

    def get(path, **kwargs):
        return copy.deepcopy(
            {
                "/scenarios": {"scenarios": scenarios},
                "/scenarios/candidate/blueprint": blueprint,
                "/scenarios/observed/blueprint": VALID_MAKE,
                "/ai-agents/v1/agents": {"agents": []},
            }[path]
        )

    monkeypatch.setattr(automation, "HttpClient", Mock(return_value=Mock(get_json=get)))


def _make_scan(index):
    return _scan(
        index, "lowcode.make", api_url="https://make.example/api/v2", token="fixture-token", team_id="1"
    )


@pytest.mark.parametrize("case", CASES["make_invalid_blueprints"], ids=lambda case: case["case"])
def test_make_invalid_blueprint_is_incomplete_through_engine(index, monkeypatch, case):
    _make_api(monkeypatch, case["response"], include_valid=True)
    result = _make_scan(index)
    assert not result.complete
    assert _exit_code(result, None) == 3
    assert result.stats[0].incomplete and result.stats[0].warnings
    assert {finding.resource for finding in result.findings} == {"make:scenario:observed"}


@pytest.mark.parametrize("case", CASES["make_valid_blueprints"], ids=lambda case: case["case"])
def test_make_valid_and_empty_blueprints_remain_complete(index, monkeypatch, case):
    _make_api(monkeypatch, case["response"])
    result = _make_scan(index)
    assert result.complete, result.stats[0].warnings
    assert _exit_code(result, None) == 0
    assert bool(result.findings) is case["finding"]
    if case["case"] == "nested-ai":
        assert result.findings[0].metadata["ai_steps"] == ["openai-gpt-3:CreateCompletion"]


@pytest.mark.parametrize("budget", ["MAX_GRAPH_NODES", "MAX_GRAPH_EDGES", "_MAKE_MAX_FLOW_DEPTH"])
def test_make_exhausted_nested_flow_budget_is_incomplete(index, monkeypatch, budget):
    blueprint = {"flow": [{"module": "builtin:BasicRouter", "routes": [{"flow": VALID_MAKE["flow"]}]}]}
    monkeypatch.setattr(automation, budget, 0 if budget != "MAX_GRAPH_NODES" else 1)
    _make_api(monkeypatch, blueprint)
    result = _make_scan(index)
    assert not result.complete and _exit_code(result, None) == 3
    assert result.stats[0].warnings


@pytest.mark.parametrize("case", CASES["zapier_invalid_pages"], ids=lambda case: case["case"])
def test_zapier_invalid_continuation_keeps_observations_and_is_incomplete(index, monkeypatch, case):
    http = Mock()
    http.get_json.side_effect = [
        {"data": [VALID_ZAP], "links": {"next": "/v2/zaps?cursor=remaining"}},
        copy.deepcopy(case["page"]),
    ]
    monkeypatch.setattr(automation, "HttpClient", Mock(return_value=http))
    result = _scan(index, "lowcode.zapier", token="fixture-token")
    assert not result.complete and _exit_code(result, None) == 3
    assert result.stats[0].incomplete
    assert {finding.resource for finding in result.findings} == {"zapier:zap:observed"}
    assert http.get_json.call_count == 2


@pytest.mark.parametrize("terminal", [None, ""])
@pytest.mark.parametrize("records", [[], [VALID_ZAP]])
def test_zapier_valid_terminal_and_empty_inventory_remain_complete(index, monkeypatch, terminal, records):
    http = Mock(get_json=Mock(return_value={"data": records, "links": {"next": terminal}}))
    monkeypatch.setattr(automation, "HttpClient", Mock(return_value=http))
    result = _scan(index, "lowcode.zapier", token="fixture-token")
    assert result.complete, result.stats[0].warnings
    assert _exit_code(result, None) == 0
    assert len(result.findings) == len(records)
    assert http.get_json.call_count == 1


def test_make_offline_metadata_without_a_definition_is_incomplete(index, tmp_path):
    source = tmp_path / "scenarios.json"
    source.write_text(json.dumps([{"id": "candidate", "name": "Routine backup"}]))
    result = _scan(index, "lowcode.make", input=str(source))
    assert not result.complete and _exit_code(result, None) == 3
    assert not result.findings
