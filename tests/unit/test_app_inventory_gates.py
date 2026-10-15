"""Inventory gates for Notion bots, Slack app ids and Auth0 clients."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import Kind
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict

MEETING_NOTES = "identity-app.meeting-notetakers"


_TEAM = {"_kind": "team", "id": "T1", "name": "Example", "domain": "example"}


def _write(tmp_path, records, name="export.json"):
    path = tmp_path / name
    path.write_text(json.dumps(records))
    return str(path)


def _notion_bot(bot_id, name=None, owner="workspace"):
    record = {"object": "user", "id": bot_id, "type": "bot", "bot": {"owner": {"type": owner}}}
    if name is not None:
        record["name"] = name
    return record


def test_notion_inventories_only_bots_with_ai_evidence_or_an_ai_name_hint(tmp_path, run_connector):
    source = _write(
        tmp_path,
        {
            "results": [
                _notion_bot("bot-1", "Claude"),
                _notion_bot("bot-2", "Issue tracker sync"),
                _notion_bot("bot-3"),
                _notion_bot("bot-4", "Gemini roadmap"),
                # Every Notion integration is a bot user: the word alone is no AI hint.
                _notion_bot("bot-5", "Jira Bot"),
            ]
        },
    )
    findings, ctx = run_connector("saas.notion", input=source)
    assert not ctx.stats.incomplete
    by_resource = {finding.resource: finding for finding in findings}
    assert set(by_resource) == {"notion:bot:bot-1", "notion:bot:bot-4"}
    assert "identity-app.anthropic-claude" in by_resource["notion:bot:bot-1"].frameworks
    # An ambiguous product name is a hint: kept, never attributed, bounded at possible.
    gemini = by_resource["notion:bot:bot-4"]
    assert gemini.frameworks == [] and gemini.metadata["potential_frameworks"] == [
        "identity-app.google-gemini"
    ]
    assert "ai-name-hint" in gemini.tags and gemini.confidence <= 0.35


@pytest.mark.parametrize(
    "name", ["Internal LLM Agent", "Acme AI Assistant", "Support GPT", "Ticket chatbot", "GPT Bot"]
)
def test_notion_keeps_bots_with_a_generic_ai_name(tmp_path, run_connector, name):
    findings, ctx = run_connector(
        "saas.notion", input=_write(tmp_path, {"results": [_notion_bot("bot-9", name)]})
    )
    assert not ctx.stats.incomplete
    assert [finding.resource for finding in findings] == ["notion:bot:bot-9"]
    finding = findings[0]
    assert finding.kind == Kind.BOT_APP and finding.frameworks == [] and finding.model_providers == []
    assert "ai-name-hint" in finding.tags
    # The name hint is a separate weak signal; the bot's own observation is bounded.
    assert 0.35 < finding.confidence < 0.7


@pytest.mark.parametrize("homepage", ["https://www.wudpecker.io", "https://tactiq.io/install"])
def test_slack_meeting_note_takers_are_recognised_by_domain(tmp_path, run_connector, homepage):
    app = {"_kind": "approved_app", "app": {"id": "A7", "name": "Notes helper", "app_homepage_url": homepage}}
    findings, _ = run_connector("saas.slack", input=_write(tmp_path, [_TEAM, app]))
    assert [finding.resource for finding in findings] == ["slack:app:A7"]
    assert MEETING_NOTES in findings[0].frameworks


@pytest.mark.parametrize("name", ["Wudpecker", "Tactiq"])
def test_meeting_note_taker_names_are_recognised(tmp_path, run_connector, name):
    app = {"_kind": "approved_app", "app": {"id": "A8", "name": name}}
    findings, _ = run_connector("saas.slack", input=_write(tmp_path, [_TEAM, app]))
    assert MEETING_NOTES in findings[0].frameworks


def test_slack_app_id_binds_a_rule_pack_client_id(tmp_path):
    index = SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "identity-app.review-assistant",
                    "name": "Review assistant",
                    "category": "identity-app",
                    "signals": [{"type": "client_id", "names": ["A0REVIEW01"], "weight": 0.9}],
                }
            )
        ]
    )
    records = [
        _TEAM,
        {"_kind": "approved_app", "app": {"id": "A0REVIEW01", "name": "Helper"}},
        {"_kind": "approved_app", "app": {"id": "A0OTHER002", "name": "Helper two"}},
    ]
    connector = SlackConnector(ConnectorContext(config={"input": _write(tmp_path, records)}, index=index))
    findings = connector.run()
    assert [finding.resource for finding in findings] == ["slack:app:A0REVIEW01"]
    assert findings[0].frameworks == ["identity-app.review-assistant"]


def _auth0_client(client_id, name, **fields):
    return {
        "_kind": "client",
        "client_id": client_id,
        "name": name,
        "app_type": "spa",
        "grant_types": ["authorization_code"],
        **fields,
    }


def test_auth0_keeps_clients_attributed_by_provider_or_product(tmp_path, run_connector):
    records = [
        _auth0_client("c-provider", "Ticket drafts", allowed_origins=["https://api.cohere.com"]),
        _auth0_client(
            "c-product",
            "tmp117 sensor bridge",
            description="Uploads sensor readings with OpenAI GPT summaries",
        ),
        _auth0_client("c-plain", "Customer portal", callbacks=["https://portal.example/cb"]),
    ]
    findings, ctx = run_connector("identity.auth0", input=_write(tmp_path, records), domain="tenant.example")
    by_resource = {finding.resource: finding for finding in findings}
    assert set(by_resource) == {"auth0:client:c-provider", "auth0:client:c-product"}
    assert by_resource["auth0:client:c-provider"].frameworks == []
    assert "provider.cohere" in by_resource["auth0:client:c-provider"].model_providers
    assert "identity-app.openai-chatgpt" in by_resource["auth0:client:c-product"].frameworks
    assert by_resource["auth0:client:c-product"].confidence > 0.9
