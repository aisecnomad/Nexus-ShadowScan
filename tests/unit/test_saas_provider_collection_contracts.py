"""Provider-shaped live responses must preserve findings and coverage status."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
import responses
from click.testing import CliRunner
from requests import ConnectionError

from shadowscan.cli import main
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.saas import github_apps as github_apps_module
from shadowscan.connectors.saas.github_apps import GitHubAppsConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


@pytest.mark.parametrize("provider", ["notion", "atlassian"])
@pytest.mark.parametrize("mode", ["live", "offline"])
@responses.activate
def test_provider_error_with_empty_collection_is_incomplete(
    fixtures, tmp_path, run_connector, provider, mode
):
    payload = json.loads((fixtures / "saas" / "live_collection_errors.json").read_text())[provider]
    if mode == "offline":
        source = tmp_path / "provider-error.json"
        source.write_text(json.dumps(payload))
        config = {"input": str(source)}
    elif provider == "notion":
        responses.get("https://api.notion.com/v1/users", json=payload)
        config = {"token": "example-token"}
    else:
        responses.get("https://acme.atlassian.net/rest/plugins/1.0/", json=payload)
        config = {
            "site": "https://acme.atlassian.net",
            "email": "admin@example.test",
            "api_token": "example-token",
            "products": ["jira"],
        }
    findings, ctx = run_connector(f"saas.{provider}", **config)
    assert findings == []
    assert ctx.stats.incomplete and (ctx.stats.warnings or ctx.stats.errors)
    assert "synthetic-provider-error-details" not in str(ctx.stats.warnings + ctx.stats.errors)


@responses.activate
def test_notion_later_error_page_keeps_previous_integrations(fixtures, run_connector):
    url = "https://api.notion.com/v1/users"
    records = json.loads((fixtures / "saas" / "notion_users.json").read_text())["results"]
    responses.get(url, json={"results": records, "has_more": True, "next_cursor": "next"})
    payload = json.loads((fixtures / "saas" / "live_collection_errors.json").read_text())["notion"]
    responses.get(url, json=payload)

    findings, ctx = run_connector("saas.notion", token="example-token")

    assert {f.resource for f in findings} == {"notion:bot:n2", "notion:bot:n3"}
    assert ctx.stats.incomplete and not ctx.stats.errors


@responses.activate
def test_atlassian_error_envelope_keeps_neighboring_product(fixtures, run_connector):
    payload = json.loads((fixtures / "saas" / "live_collection_errors.json").read_text())["atlassian"]
    responses.get("https://acme.atlassian.net/rest/plugins/1.0/", json=payload)
    responses.get(
        "https://acme.atlassian.net/wiki/rest/plugins/1.0/",
        json={"plugins": [{"key": "ai.glean.confluence", "name": "Glean AI", "userInstalled": True}]},
    )

    findings, ctx = run_connector(
        "saas.atlassian",
        site="https://acme.atlassian.net",
        email="admin@example.test",
        api_token="example-token",
    )

    assert [f.resource for f in findings] == ["atlassian:confluence:app:ai.glean.confluence"]
    assert ctx.stats.incomplete and not ctx.stats.errors


def _installation(app_id: int, slug: str) -> dict:
    return {
        "id": app_id,
        "app_id": app_id,
        "app_slug": slug,
        "account": {"login": "acme"},
        "repository_selection": "all",
        "permissions": {"contents": "write", "metadata": "read"},
        "events": ["pull_request"],
    }


@responses.activate
def test_github_apps_live_pages_billing_and_pat_are_separate_findings(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations",
        json={"total_count": 2, "installations": [_installation(101, "coderabbitai")]},
        headers={"Link": f'<{base}/installations?per_page=100&page=2>; rel="next"'},
    )
    responses.get(
        f"{base}/installations", json={"total_count": 2, "installations": [_installation(102, "claude")]}
    )
    responses.get(
        f"{base}/copilot/billing",
        json={"plan_type": "business", "seat_breakdown": {"total": 5, "active_this_cycle": 3}},
    )
    responses.get(
        f"{base}/personal-access-tokens",
        json=[
            {
                "token_id": 501,
                "token_name": "Claude workflow",
                "owner": {"login": "dev"},
                "repository_selection": "selected",
                "permissions": {"repository": {"contents": "write"}},
            }
        ],
    )

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert {f.resource for f in findings} == {
        "github:installation:101",
        "github:installation:102",
        "github:acme/copilot",
        "github:pat:501",
    }
    assert next(f for f in findings if f.resource == "github:installation:101").metadata[
        "write_permissions"
    ] == ["contents"]
    assert next(f for f in findings if f.resource == "github:pat:501").owner == "dev"
    assert ctx.stats.objects_examined == 4 and not ctx.stats.incomplete
    assert parse_qs(urlsplit(responses.calls[1].request.url).query) == {"per_page": ["100"], "page": ["2"]}


@responses.activate
def test_github_apps_optional_billing_denial_preserves_installations_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations", json={"total_count": 1, "installations": [_installation(101, "claude")]}
    )
    responses.get(f"{base}/copilot/billing", status=403, json={"message": "Billing access denied"})
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert [f.resource for f in findings] == ["github:installation:101"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any(
        warning == "Collection incomplete: HTTP 403 for https://api.github.com"
        for warning in ctx.stats.warnings
    )
    assert all("copilot/billing" not in warning for warning in ctx.stats.warnings)
    assert len(responses.calls) == 3


@responses.activate
def test_github_apps_pat_denial_does_not_reclassify_partial_scan_as_complete(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations", json={"total_count": 1, "installations": [_installation(101, "claude")]}
    )
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", status=403)

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert [f.resource for f in findings] == ["github:installation:101"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("fine-grained PAT inventory unavailable" in warning for warning in ctx.stats.warnings)
    assert "example-readonly-token" not in str(ctx.stats.warnings)


def _zoom_app(app_id: str, name: str) -> dict:
    # The Marketplace list endpoint supplies object-shaped scopes, not only strings.
    return {
        "app_id": app_id,
        "app_name": name,
        "app_description": "AI meeting notes",
        "app_type": "ZoomApp",
        "app_usage": 1,
        "app_status": "PUBLISHED",
        "app_directory_url": f"https://marketplace.zoom.us/apps/{app_id}",
        "scopes": [{"scope_name": "recording:read:admin", "scope_description": "Read recordings"}],
    }


@responses.activate
def test_zoom_live_uses_supported_categories_and_preserves_provider_scopes(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": "next"})
    responses.get(url, json={"apps": [_zoom_app("z2", "Otter.ai")], "next_page_token": ""})
    responses.get(url, json={"apps": [_zoom_app("z3", "Claude meeting assistant")], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token", account_id="acme")

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2", "zoom:app:z3"}
    assert {"recording:read:admin"} <= set(findings[0].permissions)
    assert findings[0].metadata["status"] == "PUBLISHED"
    assert findings[0].metadata["marketplace_category"] == "public"
    public_evidence = next(ev.description for ev in findings[0].evidence if ev.signal == "zoom:app")
    created_evidence = next(ev.description for ev in findings[2].evidence if ev.signal == "zoom:app")
    assert "approved public app" in public_evidence
    assert "installed" not in public_evidence.lower()
    assert "account-created app" in created_evidence
    assert not ctx.stats.incomplete and ctx.stats.objects_examined == 3
    queries = [parse_qs(urlsplit(call.request.url).query) for call in responses.calls]
    assert [query["type"] for query in queries] == [["public"], ["public"], ["account_created"]]
    assert queries[1]["next_page_token"] == ["next"]


@responses.activate
def test_zoom_partial_public_pagination_retains_records_and_collects_created_apps(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": "next"})
    responses.get(url, status=403, json={"message": "insufficient scope"})
    responses.get(url, json={"apps": [_zoom_app("z2", "Otter.ai")], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token", account_id="acme")

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("public" in warning and "403" in warning for warning in ctx.stats.warnings)
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 3


@responses.activate
def test_zoom_bad_collection_is_incomplete_even_when_created_apps_are_empty(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"error": "example-token"})
    responses.get(url, json={"apps": [], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token")

    assert findings == []
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 2


@responses.activate
def test_zoom_server_to_server_token_exchange_uses_account_credentials(run_connector):
    responses.post(
        "https://zoom.us/oauth/token", json={"access_token": "short-lived-token", "token_type": "bearer"}
    )
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": ""})
    responses.get(url, json={"apps": [], "next_page_token": ""})

    findings, ctx = run_connector(
        "saas.zoom",
        account_id="acme",
        client_id="client-id",
        client_secret="example-secret",
    )

    assert [f.resource for f in findings] == ["zoom:app:z1"]
    assert not ctx.stats.incomplete
    auth_request = responses.calls[0].request
    assert parse_qs(urlsplit(auth_request.url).query) == {
        "grant_type": ["account_credentials"],
        "account_id": ["acme"],
    }
    assert auth_request.headers["Authorization"].startswith("Basic ")
    assert responses.calls[1].request.headers["Authorization"] == "Bearer short-lived-token"


@responses.activate
def test_zoom_rejected_token_exchange_cannot_be_reported_as_empty_inventory(run_connector):
    responses.post(
        "https://zoom.us/oauth/token", json={"error": "invalid_client", "message": "example-secret"}
    )

    findings, ctx = run_connector(
        "saas.zoom",
        account_id="acme",
        client_id="client-id",
        client_secret="example-secret",
    )

    assert findings == []
    assert ctx.stats.incomplete and ctx.stats.errors
    assert "example-secret" not in str(ctx.stats.errors)
    assert len(responses.calls) == 1


def test_zoom_malformed_scopes_keep_valid_neighbors_and_mark_incomplete(tmp_path, run_connector):
    first = _zoom_app("z1", "Fathom AI Notetaker")
    first["scopes"] = "invalid:scalar"
    second = _zoom_app("z2", "Otter.ai")
    second["scopes"] = [None, {"scope_name": "recording:read:admin"}]
    second["installed_users_count"] = 0
    source = tmp_path / "zoom-apps.json"
    source.write_text(json.dumps({"apps": [first, second]}))

    findings, ctx = run_connector("saas.zoom", input=str(source))

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2"}
    assert "recording:read:admin" in findings[1].permissions
    assert "0 reported users" in next(
        ev.description for ev in findings[1].evidence if ev.signal == "zoom:app"
    )
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(ctx.stats.warnings) == 2


@responses.activate
def test_atlassian_confluence_denial_preserves_jira_inventory(run_connector):
    base = "https://acme.atlassian.net"
    responses.get(
        f"{base}/rest/plugins/1.0/",
        json={
            "plugins": [
                {
                    "key": "com.atlassian.rovo.agents",
                    "name": "Rovo Agents",
                    "userInstalled": True,
                    "enabled": True,
                },
                {"key": "plain-plugin", "name": "Plain dashboard", "userInstalled": True},
            ]
        },
    )
    responses.get(f"{base}/wiki/rest/plugins/1.0/", status=403)

    findings, ctx = run_connector(
        "saas.atlassian", site=base, email="admin@example.com", api_token="example-token"
    )

    assert [f.resource for f in findings] == ["atlassian:jira:app:com.atlassian.rovo.agents"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("confluence" in warning and "403" in warning for warning in ctx.stats.warnings)
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 2


@responses.activate
def test_atlassian_invalid_jira_collection_does_not_hide_valid_confluence_apps(run_connector):
    base = "https://acme.atlassian.net"
    responses.get(f"{base}/rest/plugins/1.0/", json={"message": "plugins missing"})
    responses.get(
        f"{base}/wiki/rest/plugins/1.0/",
        json={
            "plugins": [
                None,
                {"key": "ai.glean.confluence", "name": "Glean AI", "userInstalled": True},
            ]
        },
    )

    findings, ctx = run_connector(
        "saas.atlassian", site=base, email="admin@example.com", api_token="example-token"
    )

    assert [f.resource for f in findings] == ["atlassian:confluence:app:ai.glean.confluence"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(ctx.stats.warnings) == 2


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_github_apps_pat_inventory_is_optional(index, monkeypatch):
    ctx = context(index, org="acme", token="synthetic")
    connector = GitHubAppsConnector(ctx)

    class FakeHttp:
        def __init__(self, *args, **kwargs):
            pass

        def paginate_link(self, path, params=None, item_key=None, on_data=None):
            if "personal-access-tokens" in path:
                raise HttpError(403, "https://api.github.com" + path)
            installation = {"id": 101, "app_slug": "coderabbitai", "permissions": {}}
            if on_data is not None:
                on_data({"total_count": 1, "installations": [installation]})
            yield installation

        def try_get_json(self, path, default=None, ok_statuses=None, **kwargs):
            return None

    monkeypatch.setattr(github_apps_module, "HttpClient", FakeHttp)
    records = list(connector.collect())
    assert [r["_kind"] for r in records] == ["installation"]
    assert ctx.stats.incomplete and any(
        "PAT inventory unavailable" in warning for warning in ctx.stats.warnings
    )


def _claude_installation(**overrides):
    return {
        "id": 101,
        "app_id": 1001,
        "app_slug": "claude",
        "account": {"login": "acme"},
        "permissions": {"contents": "write"},
        "events": ["pull_request"],
        **overrides,
    }


def _pat(**overrides):
    return {
        "token_id": 501,
        "token_name": "Claude workflow",
        "owner": {"login": "developer"},
        "permissions": {"repository": {"contents": "write"}},
        **overrides,
    }


def _run_github_inventory(mode, payload, run_connector, tmp_path):
    if mode == "offline":
        source = tmp_path / "github-inventory.json"
        source.write_text(json.dumps(payload))
        return run_connector("saas.github-apps", org="acme", input=str(source))
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json=payload)
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", json=[])
    return run_connector("saas.github-apps", org="acme", token="example-token")


@pytest.mark.parametrize("mode", ["live", "offline"])
@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"total_count": None},
        {"total_count": True},
        {"total_count": False},
        {"total_count": -1},
        {"total_count": 1.0},
        {"total_count": "1"},
        {"total_count": {"opaque-provider-secret": 1}},
    ],
)
@responses.activate
def test_github_inventory_requires_valid_total_without_losing_observations(
    run_connector, tmp_path, mode, metadata
):
    payload = {**metadata, "installations": [_claude_installation()]}
    findings, ctx = _run_github_inventory(mode, payload, run_connector, tmp_path)

    assert [f.resource for f in findings] == ["github:installation:101"]
    incomplete = mode == "live" or "total_count" in metadata
    assert ctx.stats.incomplete is incomplete
    diagnostics = ctx.stats.warnings + ctx.stats.errors
    assert any("total_count" in message for message in diagnostics) is incomplete
    assert "opaque-provider-secret" not in str(ctx.stats)


@pytest.mark.parametrize("mode", ["live", "offline"])
@pytest.mark.parametrize(
    "total,ids,incomplete",
    [
        (0, [], False),
        (1, [101], False),
        (2, [101, 102], False),
        (2, [], True),
        (2, [101], True),
        (0, [101], True),
        (1, [101, 102], True),
        (2, [101, 101], True),
        (1, [101, 101], True),
    ],
)
@responses.activate
def test_github_inventory_total_matches_unique_observed_installations(
    run_connector, tmp_path, mode, total, ids, incomplete
):
    payload = {"total_count": total, "installations": [_claude_installation(id=identity) for identity in ids]}
    findings, ctx = _run_github_inventory(mode, payload, run_connector, tmp_path)

    assert {f.resource for f in findings} == {f"github:installation:{identity}" for identity in ids}
    assert ctx.stats.incomplete is incomplete
    assert bool(ctx.stats.warnings + ctx.stats.errors) is incomplete


@pytest.mark.parametrize("second_total", [3, 1, None])
@responses.activate
def test_github_inventory_changed_or_missing_page_total_retains_both_pages(run_connector, second_total):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations",
        json={"total_count": 2, "installations": [_claude_installation()]},
        headers={"Link": f'<{base}/installations?page=2>; rel="next"'},
    )
    second = {"installations": [_claude_installation(id=102)]}
    if second_total is not None:
        second["total_count"] = second_total
    responses.get(f"{base}/installations", json=second)
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101", "github:installation:102"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("total_count" in warning for warning in ctx.stats.warnings)
    assert len(responses.calls) == 4


@responses.activate
def test_github_inventory_repeated_id_across_pages_does_not_complete_total(run_connector):
    base = "https://api.github.com/orgs/acme"
    page = {"total_count": 2, "installations": [_claude_installation()]}
    responses.get(
        f"{base}/installations",
        json=page,
        headers={"Link": f'<{base}/installations?page=2>; rel="next"'},
    )
    responses.get(f"{base}/installations", json=page)
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("repeated installation ids" in warning for warning in ctx.stats.warnings)
    assert any("does not match total_count" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("mode", ["live", "offline"])
@pytest.mark.parametrize("identity", [None, "102", True, 0, -1, 102.0])
@responses.activate
def test_github_inventory_invalid_installation_id_cannot_satisfy_total(
    run_connector, tmp_path, mode, identity
):
    payload = {
        "total_count": 2,
        "installations": [_claude_installation(), _claude_installation(id=identity)],
    }
    findings, ctx = _run_github_inventory(mode, payload, run_connector, tmp_path)

    assert "github:installation:101" in {f.resource for f in findings}
    assert ctx.stats.incomplete
    diagnostics = ctx.stats.warnings + ctx.stats.errors
    assert any("invalid installation id" in message for message in diagnostics)


@pytest.mark.parametrize("records", [[], [_claude_installation()]])
@pytest.mark.parametrize("envelope", [False, True])
def test_github_legacy_offline_exports_do_not_require_provider_totals(
    run_connector, tmp_path, records, envelope
):
    payload = {"installations": records} if envelope else records
    findings, ctx = _run_github_inventory("offline", payload, run_connector, tmp_path)

    assert len(findings) == len(records)
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize("metadata", [{"id": "page"}, {"name": "page"}, {"type": "page"}])
@pytest.mark.parametrize("populated", [False, True])
def test_github_offline_installations_envelope_takes_precedence_over_page_identity(
    run_connector, tmp_path, metadata, populated
):
    payload = {
        **metadata,
        "total_count": 1 if populated else 2,
        "installations": [_claude_installation()] if populated else [],
    }
    findings, ctx = _run_github_inventory("offline", payload, run_connector, tmp_path)

    assert [f.resource for f in findings] == (["github:installation:101"] if populated else [])
    assert ctx.stats.incomplete is not populated
    assert bool(ctx.stats.warnings + ctx.stats.errors) is not populated


@pytest.mark.parametrize("collection", [None, {}, "opaque-provider-secret"])
def test_github_offline_page_identity_cannot_hide_malformed_installations(
    run_connector, tmp_path, collection
):
    payload = {"id": "page", "total_count": 0, "installations": collection}
    findings, ctx = _run_github_inventory("offline", payload, run_connector, tmp_path)

    assert findings == []
    assert ctx.stats.incomplete
    assert any("collection must be an array" in error for error in ctx.stats.errors)
    assert "opaque-provider-secret" not in str(ctx.stats)


def test_github_offline_single_installation_remains_a_native_record(run_connector, tmp_path):
    findings, ctx = _run_github_inventory("offline", _claude_installation(), run_connector, tmp_path)

    assert [f.resource for f in findings] == ["github:installation:101"]
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize("mode", ["live", "offline"])
@responses.activate
def test_github_declared_missing_installations_exit_3_from_cli(tmp_path, monkeypatch, mode):
    payload = {"total_count": 2, "installations": []}
    args = ["run", "saas.github-apps", "--set", "org=acme", "--format", "json"]
    output = tmp_path / "report.json"
    args.extend(["--output", str(output)])
    if mode == "offline":
        source = tmp_path / "installations.json"
        source.write_text(json.dumps(payload))
        args.extend(["--input", str(source)])
    else:
        monkeypatch.setenv("GITHUB_TOKEN", "example-readonly-token")
        base = "https://api.github.com/orgs/acme"
        responses.get(f"{base}/installations", json=payload)
        responses.get(f"{base}/copilot/billing", status=404)
        responses.get(f"{base}/personal-access-tokens", json=[])

    result = CliRunner().invoke(main, args)

    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["findings"] == []
    assert report["stats"][0]["incomplete"] is True
    diagnostics = report["stats"][0]["warnings"] + report["stats"][0]["errors"]
    assert any("does not match total_count" in message for message in diagnostics)


@responses.activate
def test_github_installation_denial_keeps_independent_billing_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", status=403, json={"message": "opaque-provider-secret"})
    responses.get(f"{base}/copilot/billing", json={"plan_type": "business", "seat_breakdown": {"total": 3}})
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:acme/copilot", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any(
        "installation inventory" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings
    )
    assert "opaque-provider-secret" not in str(ctx.stats)
    assert len(responses.calls) == 3


@responses.activate
def test_github_failed_installation_continuation_preserves_pages_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations",
        json={"total_count": 2, "installations": [_claude_installation()]},
        headers={"Link": f'<{base}/installations?page=2>; rel="next"'},
    )
    responses.get(f"{base}/installations", status=403)
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(responses.calls) == 4


@pytest.mark.parametrize("billing", [[], {}, {"seat_breakdown": []}, {"error": "opaque-provider-secret"}])
@responses.activate
def test_github_malformed_billing_keeps_installations_and_pat(run_connector, billing):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"total_count": 1, "installations": [_claude_installation()]})
    responses.get(f"{base}/copilot/billing", json=billing)
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@responses.activate
def test_github_billing_network_failure_keeps_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"total_count": 0, "installations": []})
    responses.get(f"{base}/copilot/billing", body=ConnectionError("opaque-provider-secret"))
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert [f.resource for f in findings] == ["github:pat:501"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@pytest.mark.parametrize(
    "bad_record",
    [
        _claude_installation(id={"invalid": "opaque-provider-secret"}),
        _claude_installation(permissions={"contents": ["write"]}),
        _claude_installation(events=[{"invalid": "opaque-provider-secret"}]),
        _claude_installation(account=["invalid"]),
        _claude_installation(app_slug={"invalid": "opaque-provider-secret"}),
        _pat(permissions={"repository": ["invalid"]}),
        _pat(owner={"login": ["invalid"]}),
        {"_kind": "unsupported", "app_slug": "claude"},
        {"_kind": "copilot_billing", "seat_breakdown": "invalid"},
    ],
)
def test_github_malformed_records_preserve_valid_neighbors(tmp_path, run_connector, bad_record):
    source = tmp_path / "github.json"
    source.write_text(json.dumps([bad_record, _claude_installation(), _pat()]))

    findings, ctx = run_connector("saas.github-apps", input=str(source), org="acme")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@responses.activate
def test_github_live_billing_kind_is_assigned_by_collector(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"total_count": 0, "installations": []})
    responses.get(
        f"{base}/copilot/billing",
        json={"_kind": "pat", "plan_type": "business", "seat_breakdown": {"total": 3}},
    )
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert [f.resource for f in findings] == ["github:acme/copilot"]
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "connector,bad,valid,resource",
    [
        (
            "saas.atlassian",
            {"key": "broken", "name": ["opaque-provider-secret"]},
            {"key": "ai.glean", "name": "Glean AI"},
            "atlassian:jira:app:ai.glean",
        ),
        (
            "saas.atlassian",
            {"key": "broken", "description": ["opaque-provider-secret"]},
            {"key": "ai.glean", "name": "Glean AI"},
            "atlassian:jira:app:ai.glean",
        ),
        (
            "saas.atlassian",
            {"key": "broken", "scopes": "read:confluence-content.all"},
            {"key": "ai.glean", "name": "Glean AI"},
            "atlassian:jira:app:ai.glean",
        ),
        (
            "saas.atlassian",
            {"key": "broken", "vendor": {"link": ["opaque-provider-secret"]}},
            {"key": "ai.glean", "name": "Glean AI"},
            "atlassian:jira:app:ai.glean",
        ),
        (
            "saas.zoom",
            {"app_id": "broken", "app_name": ["opaque-provider-secret"]},
            {"app_id": "valid", "app_name": "Fathom AI Notetaker"},
            "zoom:app:valid",
        ),
        (
            "saas.zoom",
            {"app_id": "broken", "app_description": ["opaque-provider-secret"]},
            {"app_id": "valid", "app_name": "Fathom AI Notetaker"},
            "zoom:app:valid",
        ),
        (
            "saas.zoom",
            {"app_id": "broken", "owner": {"name": "opaque-provider-secret"}},
            {"app_id": "valid", "app_name": "Fathom AI Notetaker"},
            "zoom:app:valid",
        ),
        (
            "saas.zoom",
            {"app_id": "broken", "installed_users_count": -1},
            {"app_id": "valid", "app_name": "Fathom AI Notetaker"},
            "zoom:app:valid",
        ),
    ],
)
def test_malformed_saas_apps_preserve_valid_neighbors(
    tmp_path, run_connector, connector, bad, valid, resource
):
    source = tmp_path / "apps.json"
    source.write_text(json.dumps([bad, valid]))

    findings, ctx = run_connector(connector, input=str(source))

    assert [f.resource for f in findings] == [resource]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)
