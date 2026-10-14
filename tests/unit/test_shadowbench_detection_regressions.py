from __future__ import annotations

import json

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.common import apply_matches
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Likelihood, Surface
from shadowscan.registry import Inventory, InventoryValidationError


def test_name_context_is_grouped_and_cannot_exceed_weak_confidence(index):
    matches = index.match_name("Gemini AI Assistant")
    finding = Finding(
        surface=Surface.IDENTITY,
        connector="identity.okta",
        kind=Kind.OAUTH_GRANT,
        title="Okta OAuth app: Gemini AI Assistant",
        resource="okta:app:test",
        resource_type="okta-application",
    )

    apply_matches(finding, matches)
    finding.recompute_confidence()

    name_evidence = [e for e in finding.evidence if e.signal.startswith("name:")]
    assert len(name_evidence) >= 2
    assert {e.attributes["confidence_group"] for e in name_evidence} == {"name-only"}
    assert max(e.weight for e in name_evidence) <= 0.2
    assert finding.confidence == 0.2


def test_name_negative_context_and_mcp_token_boundary(index):
    for value in (
        "Gemini Exchange Portal",
        "gemini-settlement-sync-d8r",
        "Copilot license cleanup",
        "Notion Jira Sync Bot",
    ):
        matches = index.match_name(value)
        assert not any(
            match.signature_id in {"identity-app.google-gemini", "identity-app.generic-ai-name"}
            for match in matches
        )

    assert "protocol.mcp" not in {match.signature_id for match in index.match_name("mcp2515-canbus-bridge")}
    assert "protocol.mcp" in {match.signature_id for match in index.match_name("Model Context Protocol")}


def test_identity_false_positives_and_verified_positives(run_connector, fixtures):
    findings, _ = run_connector(
        "identity.okta", input=str(fixtures / "identity" / "okta_gemini_exchange.json")
    )
    gemini = next(f for f in findings if "Gemini Trading Desk" in f.title)
    assert gemini.likelihood == Likelihood.WEAK
    fireflies = next(f for f in findings if "Fireflies.ai Notetaker" in f.title)
    assert any(e.signal.startswith("domain:") for e in fireflies.evidence)

    findings, _ = run_connector("identity.auth0", input=str(fixtures / "identity" / "auth0_mcp2515.json"))
    assert not findings

    findings, _ = run_connector(
        "identity.entra",
        input=str(fixtures / "identity" / "entra_chatgpt_grant.json"),
        tenant_id="regression-tenant",
    )
    chatgpt = next(f for f in findings if f.resource == "entra:sp:sp-chatgpt-regression")
    assert any(e.signal.startswith("domain:") for e in chatgpt.evidence)


def test_saas_name_nearmisses_and_wudpecker_positive(run_connector, fixtures):
    fields = {
        "name": "App Name",
        "scopes": "Permissions",
        "users": "Users",
        "owner": "Installed By",
        "url": "Domain",
    }
    findings, _ = run_connector(
        "saas.generic",
        input=str(fixtures / "saas" / "name_nearmisses.csv"),
        platform="google-marketplace",
        fields=fields,
    )
    assert not findings

    findings, _ = run_connector(
        "saas.generic",
        input=str(fixtures / "saas" / "generic_apps.csv"),
        platform="google-marketplace",
        fields=fields,
    )
    perplexity = next(f for f in findings if "Perplexity" in f.title)
    assert any(e.signal.startswith(("domain:", "scope:")) for e in perplexity.evidence)

    findings, _ = run_connector("saas.notion", input=str(fixtures / "saas" / "notion_jira_sync.json"))
    assert not findings

    findings, _ = run_connector("saas.slack", input=str(fixtures / "saas" / "slack_wudpecker.json"))
    wudpecker = next(f for f in findings if "Wudpecker" in f.title)
    assert "identity-app.meeting-notetakers" in wudpecker.frameworks
    assert any(e.signal.startswith("client_id:") for e in wudpecker.evidence)


def test_gcp_and_servicenow_name_nearmisses_stay_clean(run_connector, fixtures):
    findings, _ = run_connector("cloud.gcp", input=str(fixtures / "cloud" / "gcp_gemini_settlement.jsonl"))
    assert not findings

    findings, _ = run_connector(
        "lowcode.servicenow", input=str(fixtures / "lowcode" / "servicenow_copilot_cleanup.json")
    )
    assert not findings


def test_kubernetes_model_serving_corroboration_keeps_billing_control_clean(run_connector, fixtures):
    findings, _ = run_connector(
        "cloud.kubernetes",
        input=str(fixtures / "cloud" / "kubernetes_vllm.json"),
        cluster="regression-cluster",
    )
    serving = next(f for f in findings if "eta-vllm-serving" in f.title)
    assert serving.kind == Kind.AGENT
    assert "self-hosted-model-serving" in serving.tags
    assert any(e.signal == "kubernetes:model-argument" for e in serving.evidence)
    assert not any("sagemaker-billing-exporter" in f.title for f in findings)


def test_n8n_internal_model_http_node_and_control(run_connector, fixtures):
    findings, _ = run_connector("lowcode.n8n", input=str(fixtures / "lowcode" / "n8n_internal_model.json"))
    qa = next(f for f in findings if f.title.endswith("Dock manifest QA"))
    assert "HTTP Request LLM API" in " ".join(qa.metadata["ai_steps"])
    assert not any("Backup rate sheets" in f.title for f in findings)


def test_gateway_distinguishes_browser_audit_and_internal_model_calls(run_connector, fixtures):
    findings, _ = run_connector(
        "gateway.logs",
        input=str(fixtures / "gateway" / "egress_classification.log"),
        format="access-log",
        internal_model_hosts=["tgi-yard.vantor.example"],
    )
    browser = next(f for f in findings if f.metadata.get("usage_class") == "human-web-usage")
    assert browser.kind == Kind.AI_APP and browser.confidence <= 0.2
    assert any("python-httpx" in json.dumps(f.metadata) for f in findings)
    assert any("crewai" in json.dumps(f.metadata) for f in findings)
    assert not any("run-audit" in json.dumps(f.metadata) for f in findings)


def test_not_ai_inventory_is_exact_and_never_overrides_verified_evidence(tmp_path):
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text(
        "agents: []\n"
        "not_ai:\n"
        "  - id: known-exchange\n"
        "    client_id: exchange-client\n"
        "    app_id: exchange-app\n"
        "    name: Gemini Trading Desk\n"
        "    resource_ids: [okta:app:gemini-exchange]\n"
    )
    inventory = Inventory.load([inventory_path])
    finding = Finding(
        surface=Surface.IDENTITY,
        connector="identity.okta",
        kind=Kind.OAUTH_GRANT,
        title="Okta OAuth app: Gemini Trading Desk",
        resource="okta:app:gemini-exchange",
        resource_type="okta-application",
        metadata={"client_id": "exchange-client"},
    )
    finding.add_evidence(
        Evidence(
            signal="name:identity-app.google-gemini",
            description="Name matched a known product",
            signature="identity-app.google-gemini",
        )
    )
    assert inventory.name_only_suppression(finding) == "known-exchange"

    finding.add_evidence(
        Evidence(
            signal="domain:identity-app.google-gemini",
            description="Verified AI endpoint",
            signature="identity-app.google-gemini",
        )
    )
    assert inventory.name_only_suppression(finding) is None


def test_not_ai_suppression_is_reported_and_malformed_rules_incomplete(tmp_path):
    source = tmp_path / "apps.csv"
    source.write_text(
        "App Name,Publisher,Permissions,Users,Installed By,Status,Domain\nChatGPT,Finance,,1,ops,active,\n"
    )
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text("agents: []\nnot_ai:\n  - id: non-ai-chatgpt\n    name: ChatGPT\n")
    config = ScanConfig(
        connectors=[
            ConnectorSpec(
                "saas.generic",
                {
                    "input": str(source),
                    "platform": "google-marketplace",
                    "fields": {
                        "name": "App Name",
                        "scopes": "Permissions",
                        "users": "Users",
                        "owner": "Installed By",
                        "url": "Domain",
                    },
                },
            )
        ],
        inventory=[str(inventory_path)],
    )
    result = Engine(config).run()
    assert result.complete and not result.findings
    warning = next(stat for stat in result.stats if stat.connector == "engine.inventory")
    assert warning.warnings == ["not_ai rule non-ai-chatgpt: suppressed 1 name-only finding(s)"]

    inventory_path.write_text("agents: []\nnot_ai:\n  - id: invalid-rule\n    client_id: []\n")
    incomplete = Engine(config).run()
    assert not incomplete.complete
    inventory_stats = next(stat for stat in incomplete.stats if stat.connector == "engine.inventory")
    assert inventory_stats.incomplete and inventory_stats.errors
    assert "client_id" in inventory_stats.errors[0]


def test_malformed_not_ai_inventory_still_raises_in_the_schema_loader(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text("agents: []\nnot_ai: [not-a-mapping]\n")
    try:
        Inventory.load([path])
    except InventoryValidationError as exc:
        assert ".not_ai" in str(exc)
    else:
        raise AssertionError("malformed not_ai entry was accepted")
