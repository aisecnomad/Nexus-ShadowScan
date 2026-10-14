"""Ambiguous app names do not establish an AI product or independent evidence."""

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
    assert [finding.resource for finding in findings] == ["saas:app:gemini-official-domain"]
    assert GEMINI in findings[0].frameworks
    assert findings[0].metadata["agent_indicators"] == 1


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
    # A generic AI-name hint is separate evidence: a hint never lowers the score.
    assert hinted.confidence > plain.confidence
    assert hinted.confidence == pytest.approx(0.577, abs=0.001)
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
    ],
)
def test_every_host_in_a_multi_url_field_is_checked(index, redirect):
    finding = _finding()
    assess_app(index, finding, name="Custom action", urls=[redirect])
    finalize(finding, index)
    assert "identity-app.openai-chatgpt" in finding.frameworks


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
