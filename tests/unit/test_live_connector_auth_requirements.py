"""Live connectors ask each API for what its documentation requires.

Checked against the vendors' published API references, not against live
tenants: GitHub serves the approved fine-grained PAT list only to GitHub App
tokens, and the v1.0 Graph servicePrincipal resource defines neither
publisherName nor createdDateTime. Okta's grants scope is documented in the
connector listing (Slack's team_id is covered in test_slack_connector.py).
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import responses

from shadowscan.connectors import get_connector_class

API = "https://api.github.com"
ORG = "acme"
OWNER_TOKEN = "synthetic-owner-token"
APP_TOKEN = "synthetic-app-token"


def _github(installations_status: int = 200, pat_status: int = 200) -> None:
    responses.get(
        f"{API}/orgs/{ORG}/installations",
        json={"total_count": 0, "installations": []},
        status=installations_status,
    )
    responses.get(f"{API}/orgs/{ORG}/copilot/billing", json={}, status=404)
    responses.get(
        f"{API}/orgs/{ORG}/personal-access-tokens",
        json=[] if pat_status == 200 else {"message": "denied"},
        status=pat_status,
    )


def _authorization(path: str) -> list[str]:
    return [
        call.request.headers["Authorization"]
        for call in responses.calls
        if call.request.url.split("?")[0].endswith(path)
    ]


@responses.activate
def test_the_pat_list_uses_the_github_app_token_when_one_is_set(run_connector):
    _github()
    _, ctx = run_connector("saas.github-apps", org=ORG, token=OWNER_TOKEN, app_token=APP_TOKEN)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert _authorization("/installations") == [f"Bearer {OWNER_TOKEN}"]
    assert _authorization("/personal-access-tokens") == [f"Bearer {APP_TOKEN}"]


@responses.activate
def test_one_github_app_token_serves_every_call(run_connector):
    _github()
    _, ctx = run_connector("saas.github-apps", org=ORG, token=APP_TOKEN)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert _authorization("/personal-access-tokens") == [f"Bearer {APP_TOKEN}"]


@responses.activate
def test_a_refused_pat_list_without_an_app_token_is_incomplete_and_says_why(run_connector):
    _github(pat_status=403)
    _, ctx = run_connector("saas.github-apps", org=ORG, token=OWNER_TOKEN)
    assert ctx.stats.incomplete
    assert any("app_token" in warning for warning in ctx.stats.warnings)
    assert not any(OWNER_TOKEN in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize(
    ("connector", "key", "required"),
    [
        ("saas.github-apps", "app_token", "GitHub App"),
        ("identity.okta", "bearer", "okta.appGrants.read"),
        ("saas.slack", "team_id", "org-level token"),
    ],
)
def test_the_connector_listing_names_the_documented_requirement(connector, key, required):
    assert required in get_connector_class(connector).config_keys[key]


def test_the_service_principal_listing_selects_only_v1_properties(index, monkeypatch):
    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.identity import entra

    requested: list[tuple[str, dict]] = []

    class StopAfterListing(Exception):
        pass

    def pages(self, path, params=None):
        requested.append((path, dict(params or {})))
        raise StopAfterListing

    monkeypatch.setattr(entra.EntraConnector, "_auth", lambda self: setattr(self, "http", Mock()))
    monkeypatch.setattr(entra.EntraConnector, "_pages", pages)
    connector = entra.EntraConnector(
        ConnectorContext(index=index, config={"tenant_id": "t", "client_id": "c", "client_secret": "s"})
    )
    with pytest.raises(StopAfterListing):
        list(connector.collect())
    path, params = requested[0]
    selected = set(params["$select"].split(","))
    assert path == "/servicePrincipals"
    assert not selected & {"publisherName", "createdDateTime"}
    assert {"id", "appId", "displayName", "verifiedPublisher", "appOwnerOrganizationId"} <= selected
