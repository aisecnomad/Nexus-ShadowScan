"""Mutable app names do not establish an AI product or independent evidence."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.common import (
    UNATTRIBUTED_APP_MAX_WEIGHT,
    apply_matches,
    finalize,
    name_matches,
)
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict

GEMINI = "identity-app.google-gemini"


def _finding() -> Finding:
    return Finding(
        surface=Surface.IDENTITY,
        connector="identity.test",
        kind=Kind.SERVICE_IDENTITY,
        title="Application",
        resource="test:application",
        resource_type="application",
    )


def test_offline_ambiguous_names_require_product_evidence(run_connector, fixtures):
    findings, ctx = run_connector("saas.generic", input=str(fixtures / "saas/ambiguous_name_apps.json"))
    assert not ctx.stats.incomplete
    assert len(findings) == 5
    (bound,) = [finding for finding in findings if finding.frameworks]
    assert bound.resource == "saas:app:gemini-official-domain"
    assert GEMINI in bound.frameworks
    assert bound.metadata["agent_indicators"] == 1
    assert all(f.confidence <= 0.35 for f in findings if not f.frameworks)


def test_keep_all_preserves_weak_hints_without_vendor_claims(run_connector, fixtures):
    findings, ctx = run_connector(
        "saas.generic", input=str(fixtures / "saas/ambiguous_name_apps.json"), keep_all=True
    )
    assert not ctx.stats.incomplete
    assert len(findings) == 5
    for finding in findings:
        if finding.resource.endswith("gemini-official-domain"):
            continue
        assert finding.metadata["potential_frameworks"] == [GEMINI]
        assert finding.frameworks == [] and finding.model_providers == []
        assert finding.metadata["technologies"] == []
        assert finding.capabilities == []
        assert finding.metadata["agent_indicators"] == 0
        assert not {"assistant", "agent-platform"}.intersection(finding.tags)
        assert finding.confidence <= 0.35


@pytest.mark.parametrize(
    "url",
    [
        "https://api.gemini.com/v1/settlement",
        "https://gemini.google.com.portal.example/app",
        "https://portal.example/gemini.google.com/app",
        "https://portal.example/?next=https://gemini.google.com",
        "https://portal.example/#https://gemini.google.com",
        "https://gemini.google.com@portal.example/app",
        # Python reads "portal.example\\" as userinfo; a browser goes to portal.example.
        "https://portal.example\\@gemini.google.com/cb",
        "https://reviewer@gemini.google.com/cb",
        "https://gemini.google.com\\@portal.example/cb",
        "custom://gemini.google.com/app",
        "https://[invalid/app",
    ],
)
def test_url_mentions_and_lookalikes_do_not_corroborate_product(index, url):
    finding = _finding()
    assess_app(index, finding, name="Gemini", publisher="Google", urls=[url])
    finalize(finding, index)
    assert GEMINI not in finding.frameworks
    assert finding.metadata["potential_frameworks"] == [GEMINI]
    assert finding.metadata["agent_indicators"] == 0
    assert finding.confidence <= 0.2


@pytest.mark.parametrize(
    "url", ["https://gemini.google.com/app", "aistudio.google.com", "https://notebooklm.google.com/"]
)
def test_same_product_hostname_corroborates_ambiguous_name(index, url):
    finding = _finding()
    assess_app(index, finding, name="Gemini", urls=[url])
    finalize(finding, index)
    assert GEMINI in finding.frameworks
    assert GEMINI not in finding.metadata.get("potential_frameworks", [])
    assert "agent-platform" in finding.tags
    assert finding.metadata["agent_indicators"] == 1
    assert finding.confidence > 0.7


def test_unrelated_provider_domain_does_not_establish_named_product(index):
    finding = _finding()
    assess_app(index, finding, name="Gemini", urls=["https://api.openai.com/v1"])
    finalize(finding, index)
    assert "provider.openai" in finding.model_providers
    assert GEMINI not in finding.frameworks
    assert GEMINI in finding.metadata["potential_frameworks"]
    assert all(technology["id"] != GEMINI for technology in finding.metadata["technologies"])


def test_names_and_ordinary_app_observations_are_one_weak_group(index):
    finding = _finding()
    assess_app(
        index,
        finding,
        name="Gemini",
        publisher="Google Gemini",
        description="Google AI Studio, NotebookLM, Gemini",
        aliases=["Gemini Enterprise", "Google Gemini"],
        grant_types=["client_credentials"],
        scopes=["Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All"],
    )
    # A connector's generic record confidence must not turn these names into
    # an AI verdict; multiple observations of the same app are correlated.
    for signal in ("provider:app", "provider:installed", "provider:grant"):
        finding.add_evidence(Evidence(signal=signal, description="App observed", weight=0.95))
    finalize(finding, index)
    assert finding.confidence == 0.35
    assert finding.metadata["agent_indicators"] == 0
    assert finding.frameworks == [] and finding.capabilities == []
    assert {ev.attributes["confidence_group"] for ev in finding.evidence} == {"unattributed-app"}
    finding.recompute_confidence()
    assert finding.confidence == 0.35


def _test_index() -> SignatureIndex:
    signature = signature_from_dict(
        {
            "id": "identity-app.review-product",
            "name": "Review product",
            "category": "identity-app",
            "tags": ["agent-platform"],
            "capabilities": ["tool-use"],
            "agent_indicator": True,
            "signals": [
                {"type": "name", "patterns": [r"\bReview\b"], "ambiguous": True, "weight": 0.95},
                {"type": "client_id", "names": ["reviewed-client-identifier"], "weight": 0.9},
            ],
        }
    )
    return SignatureIndex([signature])


@pytest.mark.parametrize("client_id", [None, "other-client", "reviewed-client-identifier"])
def test_ambiguous_rule_pack_uses_same_product_client_binding(client_id):
    index = _test_index()
    finding = _finding()
    assess_app(index, finding, name="Review", client_id=client_id)
    finalize(finding, index)
    supported = client_id == "reviewed-client-identifier"
    assert bool(finding.frameworks) is supported
    assert ("tool-use" in finding.capabilities) is supported
    assert ("agent-platform" in finding.tags) is supported
    assert finding.metadata["agent_indicators"] == int(supported)
    assert finding.confidence > 0.8 if supported else finding.confidence <= 0.2


def test_later_non_name_evidence_replaces_potential_attribution(index):
    finding = _finding()
    apply_matches(finding, name_matches(index, "Gemini"))
    assert finding.metadata["potential_frameworks"] == [GEMINI]
    apply_matches(finding, index.match_domain("gemini.google.com"))
    finalize(finding, index)
    assert GEMINI in finding.frameworks
    assert "potential_frameworks" not in finding.metadata


def test_entra_intrinsic_agent_evidence_survives_ambiguous_name(run_connector, fixtures, tmp_path):
    records = json.loads((fixtures / "identity/entra_agent_registry.json").read_text())
    for record in records:
        if "displayName" in record:
            record["displayName"] = "Gemini"
    source = tmp_path / "entra-gemini.json"
    source.write_text(json.dumps(records))
    findings, ctx = run_connector("identity.entra", input=str(source), tenant_id="tenant-0365")
    assert not ctx.stats.incomplete
    identity = next(f for f in findings if f.metadata.get("agent_identity") is True)
    assert GEMINI not in identity.frameworks
    assert GEMINI in identity.metadata["potential_frameworks"]
    intrinsic = next(ev for ev in identity.evidence if ev.signal == "entra:agent-identity")
    assert intrinsic.weight == 0.4
    assert intrinsic.attributes.get("confidence_group") != "unverified-app-name"
    assert identity.confidence > 0.4
    package = next(f for f in findings if f.resource_type == "copilot-package")
    registry = next(ev for ev in package.evidence if ev.signal == "registry:microsoft-agent-365")
    assert registry.weight == 0.5
    assert registry.attributes["confidence_group"] == "registry-record"
    assert GEMINI not in package.frameworks


def test_explicit_llm_permission_preserves_ai_evidence_without_vendor_attribution(index):
    finding = _finding()
    assess_app(index, finding, name="Gemini", scopes=["bedrock:InvokeModel"])
    permission = next(ev for ev in finding.evidence if ev.signal == "scope:policy.llm-access-scopes")
    original_weight = permission.weight
    finalize(finding, index)
    assert permission.weight == original_weight
    assert permission.attributes.get("confidence_group") != "unverified-app-name"
    assert "policy.llm-access-scopes" in finding.tags
    assert GEMINI not in finding.frameworks


@pytest.mark.parametrize("bad", ["true", 1, None])
def test_name_ambiguity_requires_boolean(bad):
    with pytest.raises(ValueError):
        signature_from_dict(
            {
                "id": "identity-app.bad",
                "name": "Bad",
                "category": "identity-app",
                "signals": [{"type": "name", "patterns": ["Bad"], "ambiguous": bad}],
            }
        )


def _machine_app(index, name: str | None, **kwargs) -> Finding:
    finding = _finding()
    assess_app(index, finding, name=name, grant_types=["client_credentials"], **kwargs)
    finding.add_evidence(Evidence(signal="test:client", description="Client registered", weight=0.3))
    return finalize(finding, index)


def test_unattributed_app_bound_is_monotonic_in_name_evidence(index):
    plain = _machine_app(index, "nightly-reconcile-worker")
    product_named = _machine_app(index, "Gemini reconcile worker")
    hinted = _machine_app(index, "triage-agent")
    assert plain.confidence == product_named.confidence == UNATTRIBUTED_APP_MAX_WEIGHT
    # A mutable generic name is the same app observation, not corroboration.
    assert hinted.confidence == plain.confidence
    for finding in (plain, product_named, hinted):
        assert finding.frameworks == [] and finding.model_providers == []
        assert all(
            ev.weight <= UNATTRIBUTED_APP_MAX_WEIGHT
            for ev in finding.evidence
            if ev.attributes.get("confidence_group") == "unattributed-app"
        )


def test_unattributed_app_bound_survives_merge_recomputation(index):
    from shadowscan.merge import merge

    first = _machine_app(index, "Gemini reconcile worker")
    second = _machine_app(index, "Gemini reconcile worker")
    second.add_evidence(Evidence(signal="test:install", description="Installed", weight=0.9))
    second.evidence[-1].attributes["confidence_group"] = "unattributed-app"
    second.evidence[-1].weight = UNATTRIBUTED_APP_MAX_WEIGHT
    (merged,) = merge([first, second])
    merged.recompute_confidence()
    assert merged.confidence == UNATTRIBUTED_APP_MAX_WEIGHT
    assert merged.likelihood == first.likelihood


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scopes": ["bedrock:InvokeModel"]},
        {"urls": ["https://api.openai.com/v1"]},
    ],
)
def test_ai_attributed_apps_are_not_bounded(index, kwargs):
    finding = _machine_app(index, "nightly-reconcile-worker", **kwargs)
    assert finding.confidence > UNATTRIBUTED_APP_MAX_WEIGHT
    assert all(ev.attributes.get("confidence_group") != "unattributed-app" for ev in finding.evidence)


def test_registry_record_app_is_not_bounded(index):
    finding = _finding()
    assess_app(index, finding, name="nightly-reconcile-worker")
    finding.add_evidence(
        Evidence(
            signal="registry:test",
            description="Agent registry record",
            weight=0.5,
            attributes={"confidence_group": "registry-record"},
        )
    )
    finalize(finding, index)
    assert finding.confidence == 0.5


def test_domain_matches_are_counted_once_across_urls(index):
    finding = _finding()
    assess_app(
        index,
        finding,
        name="Workspace helper",
        urls=["https://gemini.google.com/app", "https://gemini.google.com/settings"],
    )
    finalize(finding, index)
    assert GEMINI in finding.frameworks
    assert finding.metadata["agent_indicators"] == 1
    assert len([ev for ev in finding.evidence if ev.signal == f"domain:{GEMINI}"]) == 1


@pytest.mark.parametrize(
    "redirect",
    [
        "https://intranet.example/cb,https://chatgpt.com/aip/oauth/callback",
        "https://intranet.example/cb, https://chatgpt.com/aip/oauth/callback",
        "https://intranet.example/cb https://chatgpt.com/aip/oauth/callback",
        "https://intranet.example/cb;https://chatgpt.com/aip/oauth/callback",
        # Whitespace always separates, even after a query; trailing separators are dropped.
        "https://intranet.example/cb?state=1 https://chatgpt.com/aip/oauth/callback",
        "https://intranet.example/cb,https://chatgpt.com,",
    ],
)
def test_every_host_in_a_multi_url_field_is_checked(index, redirect):
    finding = _finding()
    assess_app(index, finding, name="Custom action", urls=[redirect])
    finalize(finding, index)
    assert "identity-app.openai-chatgpt" in finding.frameworks


@pytest.mark.parametrize(
    "redirect",
    [
        "https://portal.example/cb?x=1;https://chatgpt.com/cb",
        "https://portal.example/cb?next=a,https://chatgpt.com/",
        "https://portal.example/cb#a,https://chatgpt.com/",
        # A comma or semicolon separates only before a new http(s) URL.
        "https://portal.example/cb;chatgpt.com",
        "https://portal.example/cb,chatgpt.com/aip",
    ],
)
def test_a_url_list_is_never_split_inside_a_query_fragment_or_path(index, redirect):
    finding = _finding()
    assess_app(index, finding, name="Custom action", urls=[redirect])
    finalize(finding, index)
    assert "identity-app.openai-chatgpt" not in finding.frameworks
    assert finding.metadata["agent_indicators"] == 0


def test_servicenow_oauth_redirect_list_keeps_a_later_ai_host(tmp_path, run_connector):
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {
                    "_table": "oauth_entity",
                    "sys_id": "oauth-1",
                    "name": "Ticket helper",
                    "client_id": "client-1",
                    "type": "client",
                    "active": "true",
                    "redirect_url": "https://intranet.example/cb,https://chatgpt.com/aip/oauth/callback",
                }
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert not ctx.stats.incomplete
    assert [finding.resource for finding in findings] == ["servicenow:oauth_entity:oauth-1"]
    assert "identity-app.openai-chatgpt" in findings[0].frameworks


def test_corroborated_ambiguous_name_keeps_its_weight(index):
    finding = _finding()
    assess_app(index, finding, name="Gemini", urls=["https://gemini.google.com/app"])
    finalize(finding, index)
    name = next(ev for ev in finding.evidence if ev.signal == f"name:{GEMINI}")
    assert "ambiguous_name" not in name.attributes and "confidence_group" not in name.attributes
    assert name.weight > 0.2
    assert finding.metadata["agent_indicators"] == 1
    assert "ai-name-hint" not in finding.tags


def test_a_match_that_does_not_establish_adds_no_signature_tags(index):
    finding = _finding()
    apply_matches(finding, index.match_domain("gemini.google.com"), establish=False)
    assert finding.frameworks == []
    assert finding.metadata["potential_frameworks"] == [GEMINI]
    assert not {"assistant", "agent-platform"}.intersection(finding.tags)


def test_an_unestablished_generic_ai_name_is_not_a_potential_product(index):
    finding = _finding()
    apply_matches(finding, index.match_name("Support GPT"), establish=False)
    assert "potential_frameworks" not in finding.metadata
    assert finding.frameworks == [] and "ai-name-hint" not in finding.tags
    assert [ev.signature for ev in finding.evidence] == ["identity-app.generic-ai-name"]


def test_app_assessment_marker_never_reaches_a_report(index):
    finding = _machine_app(index, "nightly-reconcile-worker")
    assert "_app_assessment" not in finding.metadata


def test_mutable_product_names_are_not_vendor_attribution(run_connector, fixtures):
    source = str(fixtures / "saas/mutable_name_apps.json")
    findings, ctx = run_connector("saas.generic", input=source)
    assert not ctx.stats.incomplete
    assert {f.resource for f in findings if f.frameworks} == {
        "saas:app:claude-domain",
        "saas:app:fb8d773d-7ef8-4ec0-a117-179f88add510",
    }
    assert all(f.confidence >= 0.7 for f in findings if f.frameworks)
    assert all(f.confidence <= 0.35 for f in findings if not f.frameworks)

    retained, ctx = run_connector("saas.generic", input=source, keep_all=True)
    assert not ctx.stats.incomplete
    by_id = {f.resource.rsplit(":", 1)[-1]: f for f in retained}
    for app_id in ("expense-portal", "hr-portal", "payroll-sso", "several-name-hints"):
        finding = by_id[app_id]
        assert finding.confidence <= UNATTRIBUTED_APP_MAX_WEIGHT
        assert not finding.frameworks and not finding.model_providers and not finding.capabilities
        assert finding.metadata["agent_indicators"] == 0
        assert not finding.metadata["technologies"]
    assert "identity-app.anthropic-claude" in by_id["expense-portal"].metadata["potential_frameworks"]
    assert "identity-app.openai-chatgpt" in by_id["hr-portal"].metadata["potential_frameworks"]


def test_entra_oidc_app_names_remain_provisional(run_connector, fixtures, tmp_path):
    cases = json.loads((fixtures / "saas/mutable_name_apps.json").read_text())[:4]
    records = []
    for case in cases:
        records.extend(
            [
                {
                    "_kind": "servicePrincipal",
                    "id": case["id"],
                    "appId": "app-" + case["id"],
                    "displayName": case["name"],
                    "publisherName": case.get("publisher"),
                    "description": case.get("description"),
                    "servicePrincipalType": "Application",
                },
                {
                    "_kind": "oauth2PermissionGrant",
                    "clientId": case["id"],
                    "consentType": "AllPrincipals",
                    "scope": "openid profile email",
                },
            ]
        )
    source = tmp_path / "entra-mutable-names.json"
    source.write_text(json.dumps(records))
    findings, ctx = run_connector("identity.entra", input=str(source), tenant_id="name-assurance-test")
    assert not ctx.stats.incomplete
    assert {f.resource for f in findings} == {
        "entra:sp:expense-portal",
        "entra:sp:hr-portal",
        "entra:sp:several-name-hints",
    }
    assert all(f.confidence <= UNATTRIBUTED_APP_MAX_WEIGHT for f in findings)
    assert all(not f.frameworks and not f.model_providers and not f.capabilities for f in findings)
    assert all(f.metadata["agent_indicators"] == 0 for f in findings)


@pytest.mark.parametrize("field", ["name", "publisher", "description"])
@pytest.mark.parametrize("name", ["Claude Martin Expense Portal", "Sora HR Portal", "Microsoft Copilot"])
def test_each_mutable_app_field_requires_non_name_corroboration(index, field, name):
    finding = _finding()
    fields = {"name": "Payroll SSO", field: name}
    assess_app(index, finding, **fields, grant_types=["client_credentials"])
    finding.add_evidence(Evidence(signal="test:consent", description="App consented", weight=0.9))
    finalize(finding, index)
    assert finding.confidence == UNATTRIBUTED_APP_MAX_WEIGHT
    assert not finding.frameworks and not finding.model_providers and not finding.capabilities
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize("signal_type", ["domain", "client_id", "scope"])
def test_custom_name_signatures_need_same_product_corroboration(signal_type):
    signature = signature_from_dict(
        {
            "id": "identity-app.mutable-review",
            "name": "Review",
            "category": "identity-app",
            "agent_indicator": True,
            "capabilities": ["tool-use"],
            "signals": [
                {"type": "name", "patterns": ["Review"], "weight": 0.95},
                {
                    "type": signal_type,
                    "names" if signal_type == "client_id" else "values": ["review.example"],
                    "weight": 0.9,
                },
            ],
        }
    )
    index = SignatureIndex([signature])
    hint = _finding()
    assess_app(index, hint, name="Review", publisher="Review", description="Review", aliases=["Review"])
    finalize(hint, index)
    assert hint.confidence <= 0.2 and hint.frameworks == []
    assert hint.capabilities == [] and hint.metadata["agent_indicators"] == 0

    corroborated = _finding()
    kwargs = {
        "domain": {"urls": ["https://review.example/callback"]},
        "client_id": {"client_id": "review.example"},
        "scope": {"scopes": ["review.example"]},
    }[signal_type]
    assess_app(index, corroborated, name="Review", **kwargs)
    finalize(corroborated, index)
    assert corroborated.frameworks == [signature.id] and "tool-use" in corroborated.capabilities
    assert corroborated.metadata["agent_indicators"] == 1
    assert corroborated.confidence > 0.8


def test_unrelated_domain_never_corroborates_claude_name(index):
    finding = _finding()
    assess_app(index, finding, name="Claude Martin Expense Portal", urls=["https://chatgpt.com/"])
    finalize(finding, index)
    assert "identity-app.openai-chatgpt" in finding.frameworks
    assert "identity-app.anthropic-claude" not in finding.frameworks
    assert "identity-app.anthropic-claude" in finding.metadata["potential_frameworks"]
    hint = next(ev for ev in finding.evidence if ev.signal == "name:identity-app.anthropic-claude")
    assert hint.weight <= 0.2 and hint.attributes["ambiguous_name"] is True


def test_auth0_client_metadata_names_do_not_bypass_app_assurance(run_connector, tmp_path):
    source = tmp_path / "auth0-metadata.json"
    source.write_text(
        json.dumps(
            [
                {
                    "client_id": "payroll-client",
                    "name": "Payroll SSO",
                    "app_type": "non_interactive",
                    "grant_types": ["client_credentials"],
                    "client_metadata": {"owner": "Claude Martin", "description": "Sora HR Portal"},
                }
            ]
        )
    )
    (finding,), ctx = run_connector("identity.auth0", input=str(source))
    assert not ctx.stats.incomplete
    assert finding.confidence <= UNATTRIBUTED_APP_MAX_WEIGHT
    assert not finding.frameworks and not finding.model_providers and not finding.capabilities
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize("name", ["Insurance Agent Desk", "Jira Bot", "Payroll Assistant"])
def test_generic_names_do_not_expand_scope_free_app_inventory(run_connector, tmp_path, name):
    for connector, records in (
        (
            "identity.auth0",
            [
                {
                    "client_id": "ordinary-app",
                    "name": name,
                    "app_type": "spa",
                    "grant_types": ["authorization_code"],
                }
            ],
        ),
        (
            "identity.entra",
            [{"_kind": "application", "id": "ordinary-app", "appId": "ordinary-client", "displayName": name}],
        ),
        (
            "saas.slack",
            [
                {"_kind": "team", "id": "T1", "name": "Example"},
                {"_kind": "approved_app", "app": {"id": "A1", "name": name}},
            ],
        ),
    ):
        source = tmp_path / (connector + ".json")
        source.write_text(json.dumps(records))
        findings, ctx = run_connector(connector, input=str(source))
        assert not ctx.stats.incomplete
        assert findings == []


def test_jwt_mutable_names_do_not_claim_an_ai_vendor(index):
    import jwt

    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.identity.jwt import JwtConnector

    connector = JwtConnector(ConnectorContext(index=index))
    token = jwt.encode(
        {"iss": "https://tenant.okta.com", "sub": "client", "client_name": "Claude"},
        key=None,
        algorithm="none",
    )
    finding = connector.analyze_token(token)
    assert finding is not None
    assert "identity-app.anthropic-claude" not in finding.frameworks
    assert "identity-app.anthropic-claude" in finding.metadata["potential_frameworks"]
    assert finding.metadata["agent_indicators"] == 0
    assert finding.metadata["identity_type"] == "human"
    assert finding.confidence < 0.6


@pytest.mark.parametrize("field", ["client_name", "app_displayname", "azp_name"])
@pytest.mark.parametrize("delegated", [False, True])
def test_jwt_naming_hints_do_not_promote_identity_type(index, field, delegated):
    import jwt

    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.identity.jwt import JwtConnector

    claims = {
        "iss": "https://tenant.okta.com",
        "sub": "human-user",
        "email": "human@example.org",
        field: "Claude Martin Expense Portal",
    }
    if delegated:
        claims["act"] = {"sub": "human-manager"}
    connector = JwtConnector(ConnectorContext(index=index))
    finding = connector.analyze_token(jwt.encode(claims, key=None, algorithm="none"))
    assert finding is not None
    assert finding.metadata["identity_type"] == ("delegated" if delegated else "human")
    assert finding.confidence < 0.6
    assert not any(ev.signal in {"jwt:agent", "jwt:delegated-agent"} for ev in finding.evidence)


@pytest.mark.parametrize(
    "url",
    [
        "https://portal.example/?next=x,https://claude.ai",
        "https://portal.example/#x;https://claude.ai",
        "https://portal.example/?next=https://claude.ai",
    ],
)
def test_generic_saas_preserves_url_boundaries_before_corroboration(run_connector, tmp_path, url):
    source = tmp_path / "url-mentions.json"
    source.write_text(
        json.dumps([{"id": "expense-portal", "name": "Claude Martin Expense Portal", "url": url}])
    )
    (finding,), ctx = run_connector("saas.generic", input=str(source))
    assert not ctx.stats.incomplete
    assert finding.frameworks == [] and finding.confidence <= 0.35
    assert finding.metadata["potential_frameworks"] == ["identity-app.anthropic-claude"]


@pytest.mark.parametrize("field", ["iss", "aud"])
def test_jwt_domain_mentions_do_not_establish_the_named_vendor(index, field):
    import jwt

    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.identity.jwt import JwtConnector

    claims = {"iss": "https://tenant.okta.com", "sub": "human-user", "client_name": "Claude"}
    claims[field] = "https://portal.example/?app=https://claude.ai"
    finding = JwtConnector(ConnectorContext(index=index)).analyze_token(
        jwt.encode(claims, key=None, algorithm="none")
    )
    assert finding is not None
    assert finding.frameworks == [] and finding.model_providers == []
    assert finding.metadata["identity_type"] == "human"


@pytest.mark.parametrize("surface", [Surface.CODE, Surface.ENDPOINT])
def test_app_name_policy_does_not_mutate_other_collection_contexts(index, surface):
    app = _finding()
    assess_app(index, app, name="Claude")
    assert app.frameworks == []
    installed = _finding()
    installed.surface = surface
    apply_matches(installed, name_matches(index, "Claude"))
    finalize(installed, index)
    assert "identity-app.anthropic-claude" in installed.frameworks
    assert installed.metadata["agent_indicators"] > 0
