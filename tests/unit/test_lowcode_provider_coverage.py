"""Low-code inventories preserve observed records and disclose lost coverage."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from requests import ConnectionError

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.lowcode import automation, salesforce, servicenow
from shadowscan.connectors.lowcode.automation import MakeConnector, N8nConnector
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.lowcode.servicenow import ServiceNowConnector
from shadowscan.models import Kind, ScanStats
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpError


def _live(index, cls, responses, **config):
    connector = cls(ConnectorContext(index=index, config=config))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.get_json.side_effect = responses
    return connector


@pytest.mark.parametrize(
    "page",
    [{}, {"records": None}, {"records": [], "done": False}, {"records": [], "done": True, "error": "denied"}],
)
def test_salesforce_invalid_or_truncated_page_is_incomplete(index, monkeypatch, page):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(index, salesforce.SalesforceConnector, [page])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors


@pytest.mark.parametrize(
    "failure", [HttpError(403, "https://example.test/opaque-secret"), ConnectionError("opaque-secret")]
)
def test_salesforce_later_page_failure_preserves_previous_records(index, monkeypatch, failure):
    monkeypatch.setattr(
        salesforce,
        "QUERIES",
        {"BotDefinition": ("data", "query"), "GenAiPlannerDefinition": ("tooling", "query")},
    )
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [
            {
                "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
                "done": False,
                "nextRecordsUrl": "/next",
            },
            failure,
            {"records": [{"Id": "planner-1", "DeveloperName": "Planner"}], "done": True},
        ],
    )
    findings = connector.run()
    assert {f.resource for f in findings} == {"salesforce:bot:bot-1", "salesforce:genai-planner:planner-1"}
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors
    assert "opaque-secret" not in " ".join(connector.ctx.stats.warnings)


@pytest.mark.parametrize("max_pages,expected_calls", [(1, 1), (10, 2)])
def test_salesforce_page_limit_and_repeated_links_are_bounded(index, monkeypatch, max_pages, expected_calls):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    page = {
        "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
        "done": False,
        "nextRecordsUrl": "/next",
    }
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [page, page, RuntimeError("guard against unbounded loop")],
        max_pages=max_pages,
    )
    findings = connector.run()
    assert len(findings) == 1
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete
    assert not connector.ctx.stats.errors


@pytest.mark.parametrize(
    "page", [{}, {"result": None}, {"result": "invalid"}, {"result": [], "error": "denied"}]
)
def test_servicenow_invalid_page_is_incomplete(index, monkeypatch, page):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    connector = _live(index, servicenow.ServiceNowConnector, [page])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors


@pytest.mark.parametrize("max_pages,expected_calls", [(1, 1), (10, 2)])
def test_servicenow_page_limit_and_repeated_pages_are_bounded(index, monkeypatch, max_pages, expected_calls):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    # Keep this pagination test independent of regex timing for 500 identical
    # display names. Native agent findings do not depend on name enrichment.
    match_names = Mock(return_value=[])
    monkeypatch.setattr(servicenow, "name_matches", match_names)
    page = {"result": [{"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(500)]}
    connector = _live(
        index,
        servicenow.ServiceNowConnector,
        [page, page, RuntimeError("guard against unbounded loop")],
        max_pages=max_pages,
    )
    findings = connector.run()
    assert not connector.ctx.stats.errors, connector.ctx.stats.errors
    assert len(findings) == 500
    assert match_names.call_count == 500
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete


def _snow_page(start, count):
    return {
        "result": [
            {"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(start, start + count)
        ]
    }


def _snow_counted(index, pages, total, **config):
    """A live ServiceNow connector whose Table API pages carry ``X-Total-Count: total`` (None: absent)."""
    responses = iter(pages)

    def get_json(path, *, params, on_response=None):
        item = next(responses)
        if isinstance(item, BaseException):
            raise item
        if on_response is not None and total is not None:
            on_response(Mock(headers={"X-Total-Count": str(total)}))
        return item

    connector = _live(index, servicenow.ServiceNowConnector, [], **config)
    connector.http.get_json.side_effect = get_json
    return connector


def _snow_offsets(connector):
    return [call.kwargs["params"]["sysparm_offset"] for call in connector.http.get_json.call_args_list]


def test_servicenow_short_page_is_not_the_last_page(index, monkeypatch):
    # ACLs filter rows after sysparm_limit: 100 of 500 rows came back while
    # more existed, and collection stopped with 100 findings, complete.
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    connector = _snow_counted(
        index,
        [
            _snow_page(0, 100),
            _snow_page(100, 37),
            {"result": []},
            RuntimeError("guard against unbounded loop"),
        ],
        total=1500,
    )
    findings = connector.run()
    assert len(findings) == 137
    assert _snow_offsets(connector) == [0, 500, 1000]
    assert not connector.ctx.stats.incomplete and not connector.ctx.stats.warnings


def test_servicenow_window_emptied_by_acls_is_not_the_end_of_the_table(index, monkeypatch):
    # ACLs can hide every row of a 500-row window while a later window still
    # has readable rows: the table ends at X-Total-Count, not at an empty page.
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    pages = [_snow_page(0, 40), {"result": []}, {"result": []}, _snow_page(1500, 1)]
    connector = _snow_counted(index, [*pages, RuntimeError("guard against unbounded loop")], total=1501)
    findings = connector.run()
    assert len(findings) == 41
    assert _snow_offsets(connector) == [0, 500, 1000, 1500]
    assert not connector.ctx.stats.incomplete and not connector.ctx.stats.warnings


def test_servicenow_total_count_ends_a_table_without_an_extra_request(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    pages = [_snow_page(0, 100), _snow_page(100, 37), RuntimeError("guard against unbounded loop")]
    connector = _snow_counted(index, pages, total=1000)
    assert len(connector.run()) == 137
    assert _snow_offsets(connector) == [0, 500]
    assert not connector.ctx.stats.incomplete and not connector.ctx.stats.warnings


@pytest.mark.parametrize("total", [None, "", "-1", "1e3", "9" * 13])
def test_servicenow_empty_page_without_a_total_count_is_incomplete(index, monkeypatch, total):
    # Without the count an empty page cannot prove the end of the table.
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    pages = [_snow_page(0, 40), {"result": []}, RuntimeError("guard against unbounded loop")]
    connector = _snow_counted(index, pages, total=total)
    assert len(connector.run()) == 40
    assert _snow_offsets(connector) == [0, 500]
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings == [
        "lowcode.servicenow: table sn_aia_agent sent no valid X-Total-Count; ACLs can empty a page "
        "before the end of a table, so its end is unproven and coverage is incomplete"
    ]


def test_servicenow_short_pages_up_to_the_page_bound_are_incomplete(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    connector = _live(
        index,
        servicenow.ServiceNowConnector,
        [_snow_page(0, 100), _snow_page(100, 100), RuntimeError("guard against unbounded loop")],
        max_pages=2,
    )
    assert len(connector.run()) == 200
    assert connector.http.get_json.call_count == 2
    assert connector.ctx.stats.incomplete
    assert any("pagination limit reached" in warning for warning in connector.ctx.stats.warnings)


def test_servicenow_name_matching_timeout_preserves_native_agents(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    calls = 0

    def match_names(*_args):
        nonlocal calls
        calls += 1
        if calls == 37:
            raise MatchTimeoutError("untrusted display name must not be logged")
        return []

    monkeypatch.setattr(servicenow, "name_matches", match_names)
    page = {"result": [{"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(500)]}
    connector = _snow_counted(index, [page, RuntimeError("guard against unbounded loop")], total=500)
    findings = connector.run()
    assert len(findings) == 500
    assert {finding.resource for finding in findings} == {
        f"servicenow:sn_aia_agent:agent-{number}" for number in range(500)
    }
    assert calls == 37  # remaining native records do not retry failed optional enrichment
    assert connector.http.get_json.call_count == 1
    assert connector.ctx.stats.incomplete
    assert len(connector.ctx.stats.warnings) == 1 and not connector.ctx.stats.errors
    assert "untrusted display name" not in " ".join(connector.ctx.stats.warnings)


def test_servicenow_flow_name_timeout_preserves_accumulated_native_agents(
    tmp_path, run_connector, monkeypatch
):
    match_names = Mock(side_effect=MatchTimeoutError("opaque input must not be logged"))
    monkeypatch.setattr(servicenow, "name_matches", match_names)
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "Assistant"},
                {"_table": "sys_hub_flow", "sys_id": "flow-1", "name": "Now Assist flow"},
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert {finding.resource for finding in findings} == {
        "servicenow:sn_aia_agent:agent-1",
        "servicenow:sys_hub_flow:flow-1",
    }
    assert match_names.call_count == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1 and not ctx.stats.errors
    assert "opaque input" not in " ".join(ctx.stats.warnings)


def test_servicenow_oauth_timeout_preserves_accumulated_native_agents(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    match_app = Mock(side_effect=MatchTimeoutError("opaque input must not be logged"))
    monkeypatch.setattr(servicenow, "assess_app", match_app)
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "Assistant"},
                {"_table": "oauth_entity", "sys_id": "oauth-1", "name": "AI app"},
                {"_table": "oauth_entity", "sys_id": "oauth-2", "name": "AI app"},
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert {finding.resource for finding in findings} == {"servicenow:sn_aia_agent:agent-1"}
    assert match_app.call_count == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1 and not ctx.stats.errors
    assert "opaque input" not in " ".join(ctx.stats.warnings)


def test_servicenow_native_table_export_keeps_valid_neighbors(tmp_path, run_connector):
    source = tmp_path / "table.json"
    source.write_text(
        json.dumps(
            {
                "table": "sn_aia_agent",
                "result": [
                    "bad-row",
                    {"sys_id": "bad", "description": ["invalid"]},
                    {"sys_id": "agent-1", "name": "Assistant"},
                ],
            }
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert [f.resource for f in findings] == ["servicenow:sn_aia_agent:agent-1"]
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_salesforce_malformed_token_keeps_bot_and_valid_token(tmp_path, run_connector):
    source = tmp_path / "salesforce.json"
    source.write_text(
        json.dumps(
            [
                {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
                {
                    "attributes": {"type": "OauthToken"},
                    "AppName": "Claude",
                    "UserId": "user-1",
                    "UseCount": "not-a-count",
                },
                {
                    "attributes": {"type": "OauthToken"},
                    "AppName": "Claude",
                    "UserId": "user-2",
                    "UseCount": 2,
                },
            ]
        )
    )
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert len(findings) == 2
    assert any(f.resource == "salesforce:bot:bot-1" for f in findings)
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_servicenow_reference_uses_sys_id_before_display_name(tmp_path, run_connector):
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "New display name"},
                {
                    "_table": "sn_aia_tool",
                    "sys_id": "tool-1",
                    "name": "Execute",
                    "tool_type": "script",
                    "agent": {"value": "agent-1", "display_value": "Old display name"},
                },
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete
    assert "code-exec" in findings[0].capabilities
    assert findings[0].metadata["tools"] == [{"name": "Execute", "type": "script"}]


@pytest.mark.parametrize("markers", [{"done": False}, {"done": "true"}, {"nextRecordsUrl": "/next"}])
def test_salesforce_offline_query_continuation_preserves_partial_findings(tmp_path, run_connector, markers):
    source = tmp_path / "query.json"
    source.write_text(
        json.dumps(
            {
                "records": [
                    {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
                ],
                **markers,
            }
        )
    )
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert [f.resource for f in findings] == ["salesforce:bot:bot-1"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize(
    "connector,empty",
    [
        ("lowcode.salesforce", {"records": [], "done": True}),
        ("lowcode.servicenow", {"table": "sn_aia_agent", "result": []}),
    ],
)
def test_explicit_empty_provider_exports_remain_complete(tmp_path, run_connector, connector, empty):
    source = tmp_path / "empty.json"
    source.write_text(json.dumps(empty))
    findings, ctx = run_connector(connector, input=str(source))
    assert not findings and not ctx.stats.incomplete


def test_salesforce_normal_query_pagination_is_complete(index, monkeypatch):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [
            {
                "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
                "done": False,
                "nextRecordsUrl": "/next",
            },
            {"records": [{"Id": "bot-2", "DeveloperName": "Assistant"}], "done": True},
        ],
    )
    assert len(connector.run()) == 2
    assert not connector.ctx.stats.incomplete
    assert connector.http.get_json.call_args.kwargs == {"params": None}


POWER_AI_FLOW = {
    "_kind": "flow",
    "name": "flow-ai",
    "properties": {
        "displayName": "Summarise with OpenAI",
        "connectionReferences": {"shared_openai": {"connectionName": "shared_openai"}},
    },
}


def test_power_platform_oversized_flow_keeps_valid_neighbours(tmp_path, run_connector):
    # A 3 MiB definition used to exhaust the matching budget and abort the
    # connector: 0 findings, even for valid flows after it.
    words = ["invoke", "openai", "api_key", "model=", "import", "tool", "{{", "}}", "https://example.com/x"]
    definition = " ".join(f"{words[i % len(words)]}_{i:x}" for i in range(320_000))
    assert len(definition) > 3 * 1024 * 1024
    big = {
        "_kind": "flow",
        "name": "flow-big",
        "properties": {"displayName": "Huge flow", "definition": definition},
    }
    export = tmp_path / "flows.json"
    export.write_text(json.dumps([big, POWER_AI_FLOW]))
    findings, ctx = run_connector("lowcode.power-platform", input=str(export))
    assert "Power Automate flow using OpenAI (independent publisher): Summarise with OpenAI" in [
        finding.title for finding in findings
    ]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("definition exceeds 300000 characters" in warning for warning in ctx.stats.warnings)


def test_power_platform_match_timeout_skips_only_that_record(tmp_path, run_connector, monkeypatch):
    from shadowscan.connectors.lowcode import power_platform

    real = power_platform.blob_matches

    def blob_matches(index, text, **kwargs):
        if "hostile-marker" in text:
            raise MatchTimeoutError("untrusted definition text must not be logged")
        return real(index, text, **kwargs)

    monkeypatch.setattr(power_platform, "blob_matches", blob_matches)
    hostile = {"_kind": "flow", "name": "flow-x", "properties": {"definition": {"note": "hostile-marker"}}}
    export = tmp_path / "flows.json"
    export.write_text(json.dumps([hostile, POWER_AI_FLOW]))
    findings, ctx = run_connector("lowcode.power-platform", input=str(export))
    assert [finding.title for finding in findings] == [
        "Power Automate flow using OpenAI (independent publisher): Summarise with OpenAI"
    ]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert ctx.stats.warnings == [
        "lowcode.power-platform: skipped a flow record that could not be analysed "
        "(MatchTimeoutError); coverage incomplete"
    ]


@pytest.mark.parametrize("graph", [{}, {"nodes": None}, {"nodes": {}}, {"nodes": [], "error": "denied"}])
def test_n8n_missing_or_invalid_graph_preserves_next_workflow(index, graph):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(
        return_value=iter(
            [
                {"id": "bad", "name": "unknown", **graph},
                {
                    "id": "good",
                    "name": "assistant",
                    "nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "name": "Agent"}],
                },
            ]
        )
    )
    (finding,) = connector.run()
    assert finding.resource == "n8n:workflow:good"
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def test_n8n_empty_graph_is_known_empty(index):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([{"id": "empty", "name": "Empty", "nodes": []}]))
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_salesforce_never_requests_token_values_and_survives_expired_locators(index, monkeypatch):
    assert "DeleteToken" not in salesforce.QUERIES["OauthToken"][1]
    assert "AccessToken" not in salesforce.QUERIES["OauthToken"][1]
    ctx = context(index, instance_url="https://acme.my.salesforce.com", access_token="synthetic")
    connector = SalesforceConnector(ctx)
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "SELECT Id FROM BotDefinition")})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"records": [{"Id": "1"}], "done": False, "nextRecordsUrl": "/services/data/v62.0/query/01g-2000"},
        HttpError(400, "https://acme.my.salesforce.com/services/data/v62.0/query/01g-2000"),
    ]
    assert list(connector.collect()) == [{"Id": "1", "_kind": "BotDefinition"}]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any("collection incomplete (HTTP 400)" in w for w in ctx.stats.warnings)


def test_servicenow_pagination_stops_on_a_repeated_page(index, monkeypatch):
    ctx = context(index, instance="https://acme.service-now.com", token="synthetic")
    connector = ServiceNowConnector(ctx)
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    # Every response is a fresh object, as it would be from the transport.
    connector.http.get_json.side_effect = lambda *args, **kwargs: {
        "result": [{"sys_id": str(i)} for i in range(kwargs["params"]["sysparm_limit"])]
    }
    records = list(connector.collect())
    assert len(records) == 500
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any(
        "repeated pagination page" in warning for warning in ctx.stats.warnings
    )


def test_make_missing_blueprint_and_agents_marks_scan_incomplete(monkeypatch, run_connector):
    class MakeAPI:
        def __init__(self, *args, **kwargs):
            pass

        def get_json(self, path, params=None):
            if path == "/scenarios":
                return {
                    "scenarios": [
                        {"id": "with-blueprint", "name": "Classification flow"},
                        {"id": "without-blueprint", "name": "Routine backup"},
                    ]
                }
            if path == "/scenarios/with-blueprint/blueprint":
                return {"response": {"blueprint": {"flow": [{"module": "openai:CreateCompletion"}]}}}
            if path == "/scenarios/without-blueprint/blueprint":
                raise HttpError(403, "https://eu1.make.com/api/v2/scenarios/without-blueprint/blueprint")
            if path == "/ai-agents/v1/agents":
                raise HttpError(403, "https://eu1.make.com/api/v2/ai-agents/v1/agents")
            raise AssertionError(path)

    monkeypatch.setattr(automation, "HttpClient", MakeAPI)
    findings, ctx = run_connector(
        "lowcode.make", api_url="https://eu1.make.com/api/v2", token="dummy", team_id="team-1"
    )
    assert any(f.resource == "make:scenario:with-blueprint" for f in findings)
    assert ctx.stats.incomplete
    assert not ctx.stats.errors
    assert any("blueprints unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
    assert any("AI agents unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)


def test_make_invalid_page_is_incomplete_not_fatal(index, monkeypatch):
    connector = MakeConnector(
        ConnectorContext(
            config={"api_url": "https://eu1.make.com/api/v2", "token": "synthetic", "team_id": "1"},
            index=index,
        )
    )
    http = Mock()
    http.get_json.side_effect = ValueError("Invalid JSON response")
    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=http))
    assert connector.run() == []
    assert not connector.ctx.stats.errors
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings


@pytest.mark.parametrize("max_pages", [0, -3, "many", 2.5, True])
def test_automation_page_limits_must_be_positive_integers(index, max_pages):
    # ``max(1, int(value))`` used to coerce or clamp an invalid limit silently.
    connector = _live(
        index, N8nConnector, [], api_url="https://n8n.example/api/v1", api_key="key", max_pages=max_pages
    )
    assert connector.run() == []
    assert connector.ctx.stats.skipped and connector.ctx.stats.incomplete
    assert "max_pages must be a positive integer" in (connector.ctx.stats.skip_reason or "")


def _n8n_run(index, *nodes, connections=None):
    workflow = {"id": "wf-1", "name": "Ticket routing", "nodes": list(nodes)}
    if connections is not None:
        workflow["connections"] = connections
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    findings = connector.run()
    return findings, connector.ctx.stats


def _http_node(url, method="POST", name="Call", **parameters):
    return {
        "name": name,
        "type": "n8n-nodes-base.httpRequest",
        "parameters": {"method": method, "url": url, **parameters},
    }


def _http_v2_node(url, method="POST", **parameters):
    """An HTTP Request v1-v2 node, whose method parameter is ``requestMethod``."""
    return {
        "name": "Call",
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 2,
        "parameters": {"requestMethod": method, "url": url, **parameters},
    }


_WEBHOOK = {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}}


@pytest.mark.parametrize(
    "url",
    [
        "https://llm.internal.example/v1/chat/completions",
        "https://llm.internal.example/v1/completions",
        "http://ollama.internal.example:11434/api/generate",
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
    ],
)
def test_n8n_http_request_to_a_model_generation_route_is_an_ai_step(index, url):
    findings, stats = _n8n_run(index, _WEBHOOK, _http_node(url))
    assert len(findings) == 1 and not stats.incomplete
    assert findings[0].kind == Kind.WORKFLOW
    assert any("model API" in step for step in findings[0].metadata["ai_steps"])


@pytest.mark.parametrize(
    "node",
    [
        # SMS and messaging APIs share generation-like paths.
        _http_node("https://api.nexmo.com/v1/messages"),
        _http_node("https://rest.messagebird.com/messages"),
        _http_node("https://sms.example/messages"),
        _http_node("https://forms.example/responses"),
        _http_node("https://docgen.example.com/generate"),
        _http_node("https://helpdesk.example/chat"),
        # A body with model or messages keys is not a model API.
        _http_node("https://inventory.example/cars", jsonBody='{"model": "Model S"}'),
        _http_node("https://sms.example/batch", jsonBody='{"messages": [{"to": "+10000000000"}]}'),
        # Not a POST, or not an HTTP(S) URL.
        _http_node("https://llm.internal.example/v1/chat/completions", method="GET"),
        _http_node("ftp://llm.internal.example/v1/chat/completions"),
        _http_node("https://[invalid/v1/chat/completions"),
        {"name": "Call", "type": "n8n-nodes-base.httpRequest", "parameters": {"method": "POST"}},
    ],
)
def test_n8n_http_request_to_other_apis_is_not_an_ai_step(index, node):
    findings, stats = _n8n_run(index, _WEBHOOK, node)
    assert findings == [] and not stats.incomplete


@pytest.mark.parametrize(
    "node",
    [
        # Regression (F8): HTTP Request v1-v2 name the method requestMethod.
        _http_v2_node("https://llm.internal.example/v1/chat/completions"),
        _http_v2_node("http://ollama.internal.example:11434/api/generate"),
        # Expression-mode URLs start with "=" and may template the query or port.
        _http_node("=https://llm.internal.example/v1/chat/completions?user={{ $json.u }}"),
        _http_node("= https://llm.internal.example:{{ $env.PORT }}/v1/completions"),
        _http_v2_node("=https://llm.internal.example/v1/chat/completions"),
    ],
)
def test_n8n_http_request_versions_and_expression_urls_are_ai_steps(index, node):
    findings, stats = _n8n_run(index, _WEBHOOK, node)
    assert len(findings) == 1 and not stats.incomplete
    assert any("model API" in step for step in findings[0].metadata["ai_steps"])


@pytest.mark.parametrize(
    "node",
    [
        _http_v2_node("https://llm.internal.example/v1/chat/completions", method="GET"),
        # The n8n default method is GET: no method parameter is not a POST.
        {
            "name": "Call",
            "type": "n8n-nodes-base.httpRequest",
            "parameters": {"url": "https://x.example/v1/completions"},
        },
        # A host chosen at run time cannot be classified.
        _http_node("=https://{{ $json.host }}/v1/chat/completions"),
        _http_node("=https://llm-{{ $env.REGION }}.internal.example/v1/chat/completions"),
        _http_node("={{ $json.base }}/v1/chat/completions"),
        # Expression-mode URLs keep the messaging-route rules.
        _http_node("=https://sms.example/messages?to={{ $json.phone }}"),
    ],
)
def test_n8n_http_request_unresolvable_or_non_post_versions_are_not_ai_steps(index, node):
    findings, stats = _n8n_run(index, _WEBHOOK, node)
    assert findings == [] and not stats.incomplete


_ANTHROPIC_HEADER = {"parameters": [{"name": "anthropic-version", "value": "2023-06-01"}]}
_WHATSAPP_BODY = '={"messaging_product": "whatsapp", "to": "{{ $json.phone }}", "type": "text"}'


@pytest.mark.parametrize(
    "node",
    [
        _http_node(
            "https://llm.internal.example/v1/messages", sendHeaders=True, headerParameters=_ANTHROPIC_HEADER
        ),
        _http_v2_node(
            "https://llm.internal.example/v1/messages",
            headerParametersUi={"parameter": [{"name": "Anthropic-Version", "value": "2023-06-01"}]},
        ),
        _http_node(
            "https://gateway.internal.example/v1/responses",
            sendBody=True,
            specifyBody="json",
            jsonBody='={"model": "gpt-4.1", "input": "{{ $json.text }}"}',
        ),
        _http_node(
            "https://ollama.internal.example/api/chat",
            sendBody=True,
            bodyParameters={
                "parameters": [
                    {"name": "model", "value": "llama3"},
                    {"name": "messages", "value": "={{ $json.m }}"},
                ]
            },
        ),
        # Templates that are not plain JSON: an expression outside a string, JSON.stringify.
        _http_v2_node(
            "https://llm.internal.example/v1/messages",
            jsonParameters=True,
            bodyParametersJson='{"model": "chat-7b", "messages": {{ JSON.stringify($json.m) }} }',
        ),
        _http_node(
            "https://ollama.internal.example/api/chat",
            jsonBody="={{ JSON.stringify({ model: 'llama3', prompt: $json.text }) }}",
        ),
        # Regression (F18): an unversioned /chat/completions with a model request.
        _http_node(
            "https://llm.internal.example/chat/completions",
            sendBody=True,
            jsonBody='{"model": "chat-7b", "messages": [{"role": "user", "content": "hi"}]}',
        ),
        _http_node(
            "https://gateway.internal.example/chat/completions/",
            bodyParameters={
                "parameters": [{"name": "model", "value": "m"}, {"name": "messages", "value": "x"}]
            },
        ),
    ],
)
def test_n8n_ambiguous_generation_route_counts_with_model_request_corroboration(index, node):
    findings, stats = _n8n_run(index, _WEBHOOK, node)
    assert len(findings) == 1 and not stats.incomplete
    assert any("model API" in step for step in findings[0].metadata["ai_steps"])


@pytest.mark.parametrize(
    "node",
    [
        # WhatsApp Business API (a hosted provider and an on-premises client) and a help-desk chat.
        _http_node("https://waba.360dialog.io/v1/messages", sendBody=True, jsonBody=_WHATSAPP_BODY),
        _http_node("https://whatsapp.corp.example/v1/messages", sendBody=True, jsonBody=_WHATSAPP_BODY),
        _http_node("https://helpdesk.example/api/chat"),
        _http_node("https://forms.internal.example/v1/responses", jsonBody='{"form": "nps", "input": 9}'),
        # A model key alone, or a model request the node does not send.
        _http_node("https://catalog.example/api/chat", jsonBody='{"model": "Model S"}'),
        _http_node("https://llm.internal.example/chat/completions"),
        _http_node("https://courses.example/chat/completions", jsonBody='{"model": "Model S"}'),
        # A bare /completions still never counts, even with a model request.
        _http_node("https://llm.internal.example/completions", jsonBody='{"model": "m", "prompt": "x"}'),
        _http_node(
            "https://llm.internal.example/v1/messages",
            sendBody=False,
            jsonBody='{"model": "chat-7b", "messages": []}',
            sendHeaders=False,
            headerParameters=_ANTHROPIC_HEADER,
        ),
    ],
)
def test_n8n_ambiguous_generation_route_without_corroboration_is_not_an_ai_step(index, node):
    findings, stats = _n8n_run(index, _WEBHOOK, node)
    assert findings == [] and not stats.incomplete


@pytest.mark.parametrize(
    "node_type",
    [
        "n8n-nodes-base.mistralAi",
        "n8n-nodes-mcp.mcpClient",
        "@n8n/n8n-nodes-langchain.mcpClientTool",
        # Custom and community MCP nodes: the token is followed by a capital or a separator.
        "CUSTOM.mcpClient",
        "n8n-nodes-base.mcpClient",
        "CUSTOM.MCPServer",
        "acme.mcp_bridge",
        # Regression (F7): camelCase MCP nodes after another word.
        "CUSTOM.githubMcpClient",
        "n8n-nodes-acme.acmeMcpTool",
        "CUSTOM.zapierMcp",
        "CUSTOM.acmeMCPClient",
    ],
)
def test_n8n_named_ai_and_mcp_nodes_are_still_detected(index, node_type):
    findings, _ = _n8n_run(index, {"name": "Step", "type": node_type, "parameters": {}})
    assert len(findings) == 1


@pytest.mark.parametrize(
    "node_type",
    [
        "n8n-nodes-base.mcp9808Sensor",
        "n8n-nodes-community.smcpDecoder",
        "CUSTOM.Mcp9808",
        "CUSTOM.acmeMcp9808",
        "CUSTOM.SMCPDecoder",
        "CUSTOM.trackMcpherson",
    ],
)
def test_n8n_mcp_is_matched_as_a_token(index, node_type):
    findings, _ = _n8n_run(index, _WEBHOOK, {"name": "Step", "type": node_type, "parameters": {}})
    assert findings == []


def test_n8n_chat_agent_with_tools_stays_an_agent_and_missing_connections_is_complete(index):
    agent = {"name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}}
    tool = {"name": "Lookup", "type": "@n8n/n8n-nodes-langchain.toolHttpRequest", "parameters": {}}
    findings, stats = _n8n_run(index, agent, tool)
    assert [f.kind for f in findings] == [Kind.AGENT] and not stats.incomplete


def _servicenow_flows(tmp_path, run_connector, *flows):
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [{"_table": "sys_hub_flow", "sys_id": f"flow-{n}", **flow} for n, flow in enumerate(flows)]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert not ctx.stats.incomplete
    return {finding.resource: finding for finding in findings}


def test_servicenow_copilot_license_flow_is_not_ai_from_its_name_alone(tmp_path, run_connector):
    findings = _servicenow_flows(
        tmp_path,
        run_connector,
        {"name": "Copilot seat reclamation", "description": "Reclaim unused licences monthly"},
        {"name": "Gemini account sync", "description": "Sync settlement accounts"},
    )
    assert findings == {}


def test_servicenow_provider_named_and_marked_flows_are_kept(tmp_path, run_connector):
    findings = _servicenow_flows(
        tmp_path,
        run_connector,
        {"name": "Claude ticket summary", "description": "Summarise incident notes"},
        {"name": "OpenAI incident triage", "description": "Route incidents"},
        {"name": "Now Assist summarise ticket", "description": "Summarise the ticket"},
    )
    assert set(findings) == {f"servicenow:sys_hub_flow:flow-{n}" for n in range(3)}
    assert "identity-app.anthropic-claude" in findings["servicenow:sys_hub_flow:flow-0"].frameworks
    assert "platform.servicenow-now-assist" in findings["servicenow:sys_hub_flow:flow-2"].frameworks


# Declared graph relationships are supporting metadata; they do not prove
# runtime execution, private-data access, or a prompt-injection vulnerability.
def _graph_cases():
    from pathlib import Path

    source = Path(__file__).parents[1] / "fixtures" / "lowcode" / "graph_cases.json"
    return json.loads(source.read_text())


@pytest.mark.parametrize("case", _graph_cases(), ids=lambda case: case["case"])
def test_n8n_graph_relationship_fixture(index, case):
    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph

    workflow = case["workflow"]
    result = analyze_workflow_graph(workflow, provider="n8n")
    assert result is not None and not result.issues
    assert result.metadata["potential_input_ai_egress_path"] is case["expected_path"]
    assert result.metadata["scoring"] is False
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    findings = connector.run()
    assert not connector.ctx.stats.incomplete
    # Inventory keeps the connector's existing detection as its floor: a
    # disabled agent, an unregistered langchain type and AI text in a Set node
    # are still reported as before, but they receive no graph role, so no path
    # is claimed through them. Graph metadata never adds evidence or weight.
    (finding,) = findings
    assert finding.metadata["workflow_graph"] == result.metadata
    assert all("graph" not in evidence.signal for evidence in finding.evidence)
    if case["case"] in {"non-ai", "spoofed-type", "disabled"}:
        assert result.metadata["role_counts"]["ai"] == 0
    else:
        assert finding.confidence == pytest.approx(0.99)


@pytest.mark.parametrize(
    "connections",
    [
        None,
        [],
        {"Missing": {}},
        {"Input": []},
        {"Input": {"main": "bad"}},
        {"Input": {"main": [[None]]}},
        {"Input": {"main": [[{"node": "Missing"}]]}},
        {"Input": {"main": [[{"node": []}]]}},
    ],
)
def test_n8n_malformed_graph_marks_incomplete_and_keeps_the_workflow(index, connections):
    """Regression (#220 graph review F2): a graph defect limits the graph, not the inventory."""
    from copy import deepcopy

    bad = deepcopy(_graph_cases()[0]["workflow"])
    bad["connections"] = connections
    good = deepcopy(_graph_cases()[0]["workflow"])
    good["id"] = "good"
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([bad, good]))
    findings = connector.run()
    assert [finding.resource for finding in findings] == ["n8n:workflow:graph-demo", "n8n:workflow:good"]
    assert [finding.kind for finding in findings] == [Kind.AGENT, Kind.AGENT]
    graph = findings[0].metadata["workflow_graph"]
    assert graph["status"] == "incomplete" and graph["potential_input_ai_egress_path"] is None
    assert findings[1].metadata["workflow_graph"]["status"] == "analyzed"
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings


def _agent_with(connections, *extra_nodes):
    agent = {"name": "A", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}}
    return {"id": "wf-1", "name": "Agent", "nodes": [agent, *extra_nodes], "connections": connections}


@pytest.mark.parametrize(
    "workflow",
    [
        # A connection left behind by a deleted or renamed node.
        _agent_with({"Deleted": {"main": [[{"node": "A", "type": "main", "index": 0}]]}}),
        # Two nodes with one name.
        _agent_with({}, {"name": "A", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}}),
    ],
    ids=["dangling-source", "duplicate-names"],
)
def test_n8n_graph_defects_keep_the_agent_inventory(index, workflow):
    """Regression (#220 graph review F2): the base detected these agents; graph metadata must not hide them."""
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    (finding,) = connector.run()
    assert finding.kind == Kind.AGENT
    assert finding.metadata["workflow_graph"]["status"] == "incomplete"
    assert connector.ctx.stats.incomplete


def test_n8n_null_output_slot_is_an_unconnected_branch(index):
    """n8n exports an unconnected If/Switch output as null; that is valid, not a defect."""
    branch = {"name": "B", "type": "n8n-nodes-base.if", "parameters": {}}
    workflow = _agent_with({"B": {"main": [None, [{"node": "A", "type": "main", "index": 0}]]}}, branch)
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    (finding,) = connector.run()
    assert finding.kind == Kind.AGENT
    assert finding.metadata["workflow_graph"]["status"] == "analyzed"
    assert finding.metadata["workflow_graph"]["edge_count"] == 1
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize(
    "node",
    [
        {
            "name": "H",
            "type": "n8n-nodes-base.httpRequest",
            "parameters": {"url": "https://api.openai.com/v1/chat/completions"},
        },
        {
            "name": "M",
            "type": "@n8n/n8n-nodes-langchain.lmChatOpenRouter",
            "parameters": {"model": "openai/gpt-4o"},
        },
        {"name": "E", "type": "@n8n/n8n-nodes-langchain.embeddingsOpenAi", "parameters": {}},
        {"name": "C", "type": "n8n-nodes-mcp.mcpClient", "parameters": {}},
    ],
    ids=["http-to-openai", "openrouter-model", "embeddings", "community-mcp"],
)
def test_n8n_inventory_is_not_limited_to_the_graph_type_registry(index, node):
    """Regression (#220 graph review F1): AI workflows outside the exact registry stay detected."""
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([{"id": "w1", "name": "wf", "nodes": [node]}]))
    (finding,) = connector.run()
    assert finding.kind == Kind.WORKFLOW
    assert finding.metadata["workflow_graph"]["status"] == "unavailable"
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("limit,value", [("MAX_GRAPH_NODES", 2), ("MAX_GRAPH_EDGES", 1)])
def test_n8n_graph_resource_limits_are_incomplete(index, monkeypatch, limit, value):
    from shadowscan.connectors.lowcode import graph

    monkeypatch.setattr(graph, limit, value)
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([_graph_cases()[0]["workflow"]]))
    (finding,) = connector.run()
    assert finding.metadata["workflow_graph"]["status"] == "incomplete"
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("bad_id", [None, "", "x" * 513, "Input", []])
def test_n8n_graph_rejects_missing_duplicate_or_oversized_identifiers(bad_id):
    from copy import deepcopy

    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph

    workflow = deepcopy(_graph_cases()[0]["workflow"])
    workflow["nodes"][1]["name"] = bad_id
    result = analyze_workflow_graph(workflow, provider="n8n")
    assert result.issues
    assert result.metadata["potential_input_ai_egress_path"] is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://api.openai.com/v1/responses", True),
        ("https://API.OPENAI.COM./v1/responses", True),
        ("https://api.openai.com.attacker.invalid/v1", False),
        ("https://api.openai.com@attacker.invalid/v1", False),
        ("https://example.invalid/api.openai.com", False),
        ("={{ $env.LLM_ENDPOINT }}", False),
        ("https://api.openai.com:99999/v1", False),
        ("file:///api.openai.com", False),
        ("https://[broken", False),
        (None, False),
    ],
)
def test_n8n_literal_api_sink_uses_host_boundaries(url, expected):
    from shadowscan.connectors.lowcode.graph import n8n_node_roles

    node = {"type": "n8n-nodes-base.httpRequest", "parameters": {"url": url}}
    assert ("ai" in n8n_node_roles(node)) is expected


def test_graph_missing_adjacency_is_unknown_not_disconnected(index):
    workflow = _graph_cases()[0]["workflow"]
    workflow.pop("connections")
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    (finding,) = connector.run()
    assert finding.metadata["workflow_graph"]["status"] == "unavailable"
    assert finding.metadata["workflow_graph"]["potential_input_ai_egress_path"] is None
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("provider", ["flowise", "dify"])
@pytest.mark.parametrize("edges", [{}, [None], [{"source": "start", "target": "missing"}]])
def test_other_workflow_graphs_reject_malformed_edges(provider, edges):
    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph

    graph = {"nodes": [{"id": "start", "data": {"type": "start", "name": "startAgentflow"}}], "edges": edges}
    data = {"kind": "app", "workflow": {"graph": graph}} if provider == "dify" else graph
    result = analyze_workflow_graph(data, provider=provider)
    assert result.issues
    assert result.metadata["potential_input_ai_egress_path"] is None


def test_graph_long_path_output_is_bounded_and_loops_do_not_expand_work():
    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph

    nodes = [{"name": str(i), "type": "n8n-nodes-base.set"} for i in range(60)]
    nodes[0]["type"] = "n8n-nodes-base.webhook"
    nodes[1]["type"] = "@n8n/n8n-nodes-langchain.agent"
    nodes[-1].update({"type": "n8n-nodes-base.httpRequest", "parameters": {"url": "https://example.invalid"}})
    connections = {str(i): {"main": [[{"node": str((i + 1) % 60)}]]} for i in range(60)}
    result = analyze_workflow_graph({"nodes": nodes, "connections": connections})
    assert result.metadata["potential_input_ai_egress_path"] is True
    assert result.metadata["path_length"] == 60
    assert len(result.metadata["path_node_indices"]) == 32
    assert result.metadata["path_truncated"] is True


@pytest.mark.parametrize("value", [None, [], {}, True, 1])
def test_workflow_roles_handle_malformed_provider_values(value):
    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph, n8n_node_roles

    assert not n8n_node_roles({"type": value})
    assert "egress" not in n8n_node_roles(
        {"type": "n8n-nodes-base.slack", "parameters": {"operation": value}}
    )
    workflow = {
        "nodes": [{"id": "a", "data": {"name": "startAgentflow", "inputs": {"startInputType": value}}}],
        "edges": [],
    }
    result = analyze_workflow_graph(workflow, provider="flowise")
    assert result.metadata["role_counts"]["untrusted-input"] == 0


@pytest.mark.parametrize(
    "field,value",
    [("type", "ai_tool"), ("type", []), ("index", True), ("index", -1), ("index", "0"), ("index", [])],
)
def test_n8n_connection_fields_cannot_turn_attachment_into_execution_order(index, field, value):
    from copy import deepcopy

    from shadowscan.connectors.lowcode.graph import analyze_workflow_graph

    workflow = deepcopy(_graph_cases()[0]["workflow"])
    workflow["connections"]["Input"]["main"][0][0][field] = value
    result = analyze_workflow_graph(workflow)
    assert result.issues
    assert result.metadata["potential_input_ai_egress_path"] is None
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    (finding,) = connector.run()
    assert finding.metadata["workflow_graph"]["potential_input_ai_egress_path"] is None
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("node_type,ai", [("lmChatXAiGrok", True), ("lmChatXAi", False)])
def test_n8n_xai_model_registry_uses_actual_registered_name(index, node_type, ai):
    from shadowscan.connectors.lowcode.graph import n8n_node_roles

    node = {"name": "model", "type": "@n8n/n8n-nodes-langchain." + node_type}
    assert ("ai" in n8n_node_roles(node)) is ai
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([{"id": "xai", "nodes": [node], "connections": {}}]))
    # The exact registry decides graph roles only; inventory still reports any
    # langchain node, as the connector did before the graph core.
    (finding,) = connector.run()
    assert finding.metadata["workflow_graph"]["role_counts"]["ai"] == int(ai)
    assert not connector.ctx.stats.incomplete


def test_n8n_graph_ordinals_and_counts_use_the_inventoried_node_list(index):
    """Regression (#220 graph review F8): graph and inventory describe the same nodes."""
    workflow = {
        "id": "wf-1",
        "name": "Mixed",
        "nodes": [
            {"name": "Input", "type": "n8n-nodes-base.webhook", "parameters": {}},
            {"name": "Broken", "type": "n8n-nodes-base.set", "parameters": "not a mapping"},
            {"name": "AI", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
            {
                "name": "HTTP",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {"url": "https://example.invalid"},
            },
        ],
        "connections": {
            "Input": {"main": [[{"node": "AI", "type": "main", "index": 0}]]},
            "AI": {"main": [[{"node": "HTTP", "type": "main", "index": 0}]]},
        },
    }
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([workflow]))
    (finding,) = connector.run()
    graph = finding.metadata["workflow_graph"]
    assert graph["node_count"] == finding.metadata["node_count"] == 3
    # Ordinals index the inventoried nodes in export order: Input, AI, HTTP.
    assert graph["path_node_indices"] == [0, 1, 2]
    assert connector.ctx.stats.incomplete  # the invalid node itself is still a coverage gap


def _ai_workflow(number):
    return {
        "id": f"wf{number}",
        "name": f"Agent {number}",
        "nodes": [
            {"name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": {}},
            {"name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
        ],
        "connections": {"Webhook": {"main": [[{"node": "AI Agent", "type": "main", "index": 0}]]}},
    }


def test_n8n_workflow_with_dify_like_fields_keeps_every_workflow(index):
    """Regression (#220 verifier): an n8n record shaped like a Dify app crashed the whole export."""
    odd = {
        "id": "wf0",
        "name": "Odd",
        "kind": "app",
        "workflow": {},
        "nodes": [{"name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}}],
        "connections": {},
    }
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([odd, *(_ai_workflow(n) for n in range(1, 5))]))
    findings = connector.run()
    assert not connector.ctx.stats.errors and not connector.ctx.stats.incomplete
    assert {f.metadata["workflow_graph"]["provider"] for f in findings} == {"n8n"}
    assert sorted(f.resource for f in findings) == [f"n8n:workflow:wf{n}" for n in range(5)]


@pytest.mark.parametrize("failure", ["none", "raises"])
def test_n8n_graph_failure_is_contained_to_its_workflow(index, monkeypatch, failure):
    original = automation.analyze_workflow_graph

    def flaky(data, *, provider=None):
        if data.get("id") == "wf1":
            if failure == "none":
                return None
            raise RuntimeError("unexpected graph defect")
        return original(data, provider=provider)

    monkeypatch.setattr(automation, "analyze_workflow_graph", flaky)
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([_ai_workflow(n) for n in range(1, 5)]))
    findings = connector.run()
    assert len(findings) == 4 and not connector.ctx.stats.errors
    assert connector.ctx.stats.incomplete
    assert any("graph coverage incomplete" in warning for warning in connector.ctx.stats.warnings)
    statuses = {f.resource: f.metadata["workflow_graph"]["status"] for f in findings}
    assert statuses == {
        "n8n:workflow:wf1": "incomplete",
        **{f"n8n:workflow:wf{n}": "analyzed" for n in range(2, 5)},
    }
