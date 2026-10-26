"""An empty page must not turn a partial provider export into a clean scan."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.identity.auth0 import Auth0Connector
from shadowscan.connectors.lowcode.automation import ZapierConnector
from shadowscan.connectors.saas.slack import SlackConnector


@pytest.mark.parametrize(
    "pagination",
    [
        {"response_metadata": {"next_cursor": "opaque-page-secret"}},
        {"next_cursor": "opaque-page-secret"},
        {"IsTruncated": True},
        {"NextMarker": "opaque-page-secret"},
    ],
)
@pytest.mark.parametrize("suffix", ["json", "jsonl", "yaml"])
def test_partial_slack_export_is_incomplete(tmp_path, pagination, suffix):
    import yaml

    source = tmp_path / f"partial.{suffix}"
    body = {"ok": True, "approved_apps": [], **pagination}
    source.write_text(yaml.safe_dump(body) if suffix == "yaml" else json.dumps(body))
    result = CliRunner().invoke(main, ["run", "saas.slack", "--input", str(source), "--format", "json"])

    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["findings"] == []
    assert "uncollected next page" in result.output
    assert "opaque-page-secret" not in result.output


@pytest.mark.parametrize(
    "pagination",
    [
        {"response_metadata": []},
        {"response_metadata": {"next_cursor": []}},
        {"next_cursor": False},
        {"has_more": 0},
        {"IsTruncated": None},
    ],
)
def test_malformed_pagination_preserves_observed_records(pagination):
    errors = []
    record = {"id": "observed-agent"}
    assert list(BaseConnector._unwrap({"items": [record], **pagination}, errors.append)) == [record]
    assert errors == ["offline export has invalid pagination metadata"]


@pytest.mark.parametrize(
    "key",
    [
        "next_page_token",
        "nextPageToken",
        "nextToken",
        "NextToken",
        "NextMarker",
        "@odata.nextLink",
        "nextLink",
        "nextCursor",
        "next_cursor",
        "next_page",
        "nextPage",
    ],
)
@pytest.mark.parametrize("value", [False, 0, [], {}])
def test_falsey_malformed_cursors_cannot_attest_complete_collection(key, value):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], key: value}, errors.append)) == []
    assert errors == ["offline export has invalid pagination metadata"]


@pytest.mark.parametrize("key", ["next_page", "nextPage"])
@pytest.mark.parametrize("value", [2, "2", "https://example.test/items?page=2"])
def test_page_number_and_link_continuations_remain_incomplete(key, value):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], key: value}, errors.append)) == []
    assert errors == ["offline export contains an uncollected next page"]


@pytest.mark.parametrize(
    "pagination",
    [
        {},
        {"response_metadata": {}},
        {"response_metadata": {"next_cursor": ""}},
        {"response_metadata": {"next_cursor": None}},
        {"has_more": False, "next_cursor": None},
        {"IsTruncated": False},
    ],
)
def test_terminal_pagination_remains_complete(pagination):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], **pagination}, errors.append)) == []
    assert errors == []


def test_native_resource_pagination_named_fields_are_not_envelope_metadata():
    record = {"id": "resource", "response_metadata": {"next_cursor": "application-data"}}
    assert list(BaseConnector._unwrap(record)) == [record]


def test_gateway_context_envelope_marks_partial_export_incomplete(tmp_path, run_connector):
    source = tmp_path / "partial.json"
    source.write_text(json.dumps({"logEvents": [], "next_cursor": "opaque-page-secret"}))
    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert any("uncollected next page" in error for error in ctx.stats.errors)
    assert "opaque-page-secret" not in str(ctx.stats.errors)


_ZAP = {"id": "zap-1", "title": "Summarise leads", "steps": [{"app": {"title": "ChatGPT (OpenAI)"}}]}
_CLIENT = {"client_id": "client-1", "name": "support-agent", "app_type": "non_interactive"}
_LOG = {"app_id": "A1", "change_type": "added", "user_name": "installer", "date": "1724000000"}

# One saved page of a provider continuation the shared cursor check does not
# read: Zapier links.next, Auth0 include_totals and checkpoint pages, and the
# page numbers of Slack team.integrationLogs.
_PARTIAL_PROVIDER_PAGES = [
    pytest.param(
        ZapierConnector,
        {
            "data": [_ZAP],
            "links": {"next": "https://api.zapier.com/v2/zaps?opaque-page-secret", "prev": None},
        },
        {},
        id="zapier-links-next",
    ),
    pytest.param(
        Auth0Connector,
        {"start": 0, "limit": 100, "length": 1, "total": 250, "clients": [_CLIENT]},
        {},
        id="auth0-include-totals",
    ),
    pytest.param(
        Auth0Connector, {"clients": [_CLIENT], "next": "opaque-page-secret"}, {}, id="auth0-checkpoint"
    ),
    pytest.param(
        SlackConnector,
        {"ok": True, "logs": [_LOG], "paging": {"count": 1, "total": 3, "page": 1, "pages": 3}},
        {"team_id": "T1"},
        id="slack-integration-logs",
    ),
]


def _collection(page):
    return next(value for key, value in page.items() if key in {"data", "clients", "logs"})


@pytest.mark.parametrize(("connector", "page", "options"), _PARTIAL_PROVIDER_PAGES)
def test_provider_continuation_keeps_records_but_reports_next_page(connector, page, options):
    errors = []
    assert list(connector._unwrap(page, errors.append)) == _collection(page)
    assert errors == ["offline export contains an uncollected next page"]


@pytest.mark.parametrize(("connector", "page", "options"), _PARTIAL_PROVIDER_PAGES)
def test_partial_provider_page_export_is_incomplete(tmp_path, connector, page, options):
    source = tmp_path / "page.json"
    source.write_text(json.dumps(page))
    settings = [part for key, value in options.items() for part in ("--set", f"{key}={value}")]
    result = CliRunner().invoke(
        main, ["run", connector.name, "--input", str(source), *settings, "--format", "json"]
    )

    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["summary"]["incomplete_reasons"] == {"unscanned-input": 1}
    assert "opaque-page-secret" not in result.output


@pytest.mark.parametrize(
    ("connector", "page"),
    [
        (ZapierConnector, {"data": [_ZAP]}),
        (ZapierConnector, {"data": [_ZAP], "links": {"next": None, "prev": "/v2/zaps?offset=0"}}),
        (ZapierConnector, {"data": [_ZAP], "links": {"next": ""}}),
        (Auth0Connector, {"clients": [_CLIENT]}),
        (Auth0Connector, {"start": 100, "limit": 100, "length": 1, "total": 101, "clients": [_CLIENT]}),
        (Auth0Connector, {"clients": [_CLIENT], "next": ""}),
        (SlackConnector, {"ok": True, "logs": [_LOG]}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {"page": 3, "pages": 3}}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {"pages": 1}}),
        (SlackConnector, {"ok": True, "logs": [], "paging": {"page": 1, "pages": 0}}),
    ],
)
def test_provider_terminal_page_remains_complete(connector, page):
    errors = []
    assert list(connector._unwrap(page, errors.append)) == _collection(page)
    assert errors == []


@pytest.mark.parametrize(
    ("connector", "page"),
    [
        (ZapierConnector, {"data": [_ZAP], "links": None}),
        (ZapierConnector, {"data": [_ZAP], "links": []}),
        (ZapierConnector, {"data": [_ZAP], "links": {}}),
        (ZapierConnector, {"data": [_ZAP], "links": {"next": False}}),
        (ZapierConnector, {"data": [_ZAP], "links": {"next": " "}}),
        (Auth0Connector, {"clients": [_CLIENT], "total": "250"}),
        (Auth0Connector, {"clients": [_CLIENT], "total": True}),
        (Auth0Connector, {"clients": [_CLIENT], "total": 250, "start": None}),
        (Auth0Connector, {"clients": [_CLIENT], "total": -1}),
        (Auth0Connector, {"clients": [_CLIENT], "next": 0}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": None}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {}}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {"page": 1, "pages": "3"}}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {"page": 0, "pages": 1}}),
        (SlackConnector, {"ok": True, "logs": [_LOG], "paging": {"page": 1, "pages": 0}}),
    ],
)
def test_malformed_provider_continuation_preserves_observed_records(connector, page):
    errors = []
    assert list(connector._unwrap(page, errors.append)) == _collection(page)
    assert errors == ["offline export has invalid pagination metadata"]
