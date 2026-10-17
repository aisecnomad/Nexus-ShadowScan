"""Identity classification: privileged-scope names, agent claims, workload issuers, unverified tokens."""

from __future__ import annotations

import json
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.signatures import SignatureIndex

JWKS_URL = "https://keys.example/jwks"
OKTA_ISSUER = "https://acme.okta.com/oauth2/default"
PRIVILEGED = "policy.privileged-scopes"


def _token(claims: dict) -> str:
    return jwt.encode(claims, key=None, algorithm="none")


def _analyze(index: SignatureIndex, claims: dict, **config):
    connector = JwtConnector(ConnectorContext(index=index, config=config))
    finding = connector.analyze_token(_token(claims), **({"jwks_url": config["jwks_url"]} if config else {}))
    assert finding is not None
    return finding


# ------------------------------------------------------ privileged scope names
@pytest.mark.parametrize(
    "scope", ["offline_access", "refresh_token", "web", "api", "full", "workflow", "admin", "OFFLINE_ACCESS"]
)
def test_ambiguous_or_standard_scope_names_are_not_privileged(index: SignatureIndex, scope: str):
    assert PRIVILEGED not in {m.signature_id for m in index.match_scope(scope)}


@pytest.mark.parametrize(
    "scope",
    [
        "Directory.ReadWrite.All",
        "Mail.ReadWrite",
        "okta.users.manage",
        "admin:org",
        "admin.users:write",
        "sudo",
        "https://www.googleapis.com/auth/admin.directory.user",
        "iam:PassRole",
    ],
)
def test_distinctly_privileged_scopes_stay_privileged(index: SignatureIndex, scope: str):
    assert PRIVILEGED in {m.signature_id for m in index.match_scope(scope)}


def test_oidc_token_with_offline_access_carries_no_privileged_factor(index: SignatureIndex):
    finding = _analyze(
        index, {"iss": OKTA_ISSUER, "sub": "u1", "scp": "openid profile offline_access User.Read"}
    )
    assert PRIVILEGED not in finding.tags
    assert not [factor for factor in finding.risk.factors if PRIVILEGED in factor.id]


def test_okta_app_with_only_offline_access_is_not_flagged_privileged(run_connector, tmp_path):
    export = tmp_path / "okta.json"
    export.write_text(
        json.dumps(
            [
                {
                    "id": "0oa1wiki",
                    "name": "oidc_client",
                    "label": "Plain Wiki",
                    "status": "ACTIVE",
                    "signOnMode": "OPENID_CONNECT",
                    "settings": {"oauthClient": {"grant_types": ["authorization_code", "refresh_token"]}},
                    "credentials": {"oauthClient": {"client_id": "wiki-client"}},
                    "_grants": [{"scopeId": "offline_access"}],
                    "_tokens": [{"userId": "u1", "scopes": ["openid", "offline_access"]}],
                }
            ]
        )
    )
    findings, ctx = run_connector("identity.okta", input=str(export), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    assert not [finding for finding in findings if PRIVILEGED in finding.tags]


# --------------------------------------------------------- agent claim values
@pytest.mark.parametrize(
    "claim",
    [
        {"bot": False},
        {"bot": "false"},
        {"purpose": ""},
        {"purpose": "   "},
        {"tools": []},
        {"agent": ""},
        {"actor": None},
        {"workload": {}},
        {"delegation": 0},
        {"tool": "none"},
    ],
)
def test_empty_or_false_agent_claims_do_not_make_an_agent(index: SignatureIndex, claim: dict):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "email": "u1@acme.example", **claim})
    assert finding.metadata["identity_type"] == "human"
    assert "agent-claims" not in finding.tags
    assert finding.metadata["agent_claims"] == {}


@pytest.mark.parametrize(
    "claim", [{"bot": True}, {"agent_id": "negotiator-7"}, {"tools": ["search"]}, {"workload": "nightly-etl"}]
)
def test_meaningful_agent_claims_still_make_an_agent(index: SignatureIndex, claim: dict):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "email": "u1@acme.example", **claim})
    assert finding.metadata["identity_type"] == "agent"
    assert "agent-claims" in finding.tags
    assert list(claim) == list(finding.metadata["agent_claims"])


# ------------------------------------------------------------ workload issuers
def test_github_actions_oidc_token_is_a_workload_not_a_human_or_agent(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:acme/app:ref:refs/heads/main",
            "aud": "sts.amazonaws.com",
            # GitHub's `actor` names the user who triggered the run; it is not an agent claim.
            "actor": "octocat",
            "repository": "acme/app",
        },
    )
    assert finding.metadata["issuer_family"] == "github-actions"
    assert finding.metadata["identity_type"] == "workload"
    assert "identity:workload" in finding.tags
    assert "agent-claims" not in finding.tags


_GITHUB_ACTIONS = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:acme/app:ref:refs/heads/main",
    "aud": "sts.amazonaws.com",
    "repository": "acme/app",
}


@pytest.mark.parametrize(
    "claim,framework",
    [
        ({"actor": "claude[bot]"}, "coding-agent.claude-code"),
        ({"actor": "copilot-swe-agent[bot]"}, "coding-agent.github-copilot"),
        ({"actor": "devin-ai-integration[bot]"}, "identity-app.coding-assistants-saas"),
        (
            {"actor": "octocat", "triggering_actor": "chatgpt-codex-connector[bot]"},
            "coding-agent.openai-codex",
        ),
    ],
)
def test_github_actions_run_started_by_an_ai_agent_keeps_its_agent_claims(
    index: SignatureIndex, claim: dict, framework: str
):
    finding = _analyze(index, {**_GITHUB_ACTIONS, **claim})
    agent_claims = {key: value for key, value in claim.items() if value != "octocat"}
    assert finding.metadata["identity_type"] == "workload"
    assert finding.metadata["agent_claims"] == agent_claims
    assert "agent-claims" in finding.tags
    assert framework in finding.frameworks


@pytest.mark.parametrize(
    "claim",
    [
        {"actor": "octocat"},
        # Every GitHub App login ends in [bot]; that alone does not name an AI agent.
        {"actor": "dependabot[bot]"},
        {"actor": "github-actions[bot]", "triggering_actor": "renovate[bot]"},
    ],
)
def test_github_actions_run_started_by_a_person_or_ordinary_bot_has_no_agent_claims(
    index: SignatureIndex, claim: dict
):
    finding = _analyze(index, {**_GITHUB_ACTIONS, **claim})
    assert finding.metadata["identity_type"] == "workload"
    assert finding.metadata["agent_claims"] == {}
    assert "agent-claims" not in finding.tags
    assert finding.frameworks == []


def test_kubernetes_service_account_token_is_a_workload(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:payments:worker",
            "kubernetes.io": {"namespace": "payments", "serviceaccount": {"name": "worker", "uid": "u-1"}},
        },
    )
    assert finding.metadata["issuer_family"] == "kubernetes"
    assert finding.metadata["identity_type"] == "workload"


GKE_ISSUER = "https://container.googleapis.com/v1/projects/acme/locations/us-central1/clusters/prod"
_BOUND_CLAIMS = {
    "kubernetes.io": {"namespace": "payments", "serviceaccount": {"name": "worker", "uid": "u-1"}}
}


@pytest.mark.parametrize(
    "issuer,claims",
    [
        (GKE_ISSUER, {"sub": "system:serviceaccount:payments:worker", **_BOUND_CLAIMS}),
        (GKE_ISSUER, {"sub": "system:serviceaccount:payments:worker"}),
        (GKE_ISSUER, {"sub": "worker", **_BOUND_CLAIMS}),
        ("https://idp.acme.example", {"sub": "system:serviceaccount:payments:worker"}),
    ],
)
def test_kubernetes_service_account_token_is_a_workload_for_any_issuer(
    index: SignatureIndex, issuer: str, claims: dict
):
    finding = _analyze(index, {"iss": issuer, **claims})
    assert finding.metadata["identity_type"] == "workload"
    assert "identity:workload" in finding.tags and "identity:human" not in finding.tags
    # The issuer family still names the issuer (and keeps its hygiene rules).
    assert finding.metadata["issuer_family"] == ("google" if issuer == GKE_ISSUER else "custom")


@pytest.mark.parametrize("sub", ["serviceaccount:payments:worker", "user:system:serviceaccount:x:y", "alice"])
def test_google_token_without_kubernetes_service_account_claims_is_not_a_workload(
    index: SignatureIndex, sub: str
):
    finding = _analyze(index, {"iss": GKE_ISSUER, "sub": sub, "email": "alice@acme.example"})
    assert finding.metadata["identity_type"] == "human"


def test_gitlab_ci_job_token_is_a_workload_but_a_gitlab_sign_in_is_not(index: SignatureIndex):
    ci = _analyze(
        index,
        {"iss": "https://gitlab.com", "sub": "project_path:acme/app:ref_type:branch:ref:main", "job_id": "9"},
    )
    assert ci.metadata["identity_type"] == "workload"
    sign_in = _analyze(index, {"iss": "https://gitlab.com", "sub": "42", "email": "dev@acme.example"})
    assert sign_in.metadata["identity_type"] == "human"


def test_workload_issuer_does_not_downgrade_delegation(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:acme/app:ref:refs/heads/main",
            "act": {"sub": "deploy-bot"},
        },
    )
    assert finding.metadata["identity_type"] == "delegated-agent"


# -------------------------------------------------------- signature provenance
def test_token_without_jwks_is_explicitly_marked_unverified(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://login.microsoftonline.com/tenant/v2.0",
            "sub": "forged",
            "scp": "Mail.ReadWrite Directory.ReadWrite.All",
        },
    )
    assert finding.metadata["signature_verified"] is False
    assert "signature-unverified" in finding.tags
    evidence = next(e for e in finding.evidence if e.signal == "jwt:signature")
    assert "not checked" in evidence.description and "no jwks_url" in evidence.description
    assert evidence.weight == 0.0
    # Only the explicit marker is new: the privileged-claim evidence is not boosted or hidden.
    assert PRIVILEGED in finding.tags


def test_unverified_marker_adds_no_confidence_or_risk(index: SignatureIndex):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "scp": "okta.users.manage"})
    marker = next(e for e in finding.evidence if e.signal == "jwt:signature")
    assert marker.weight == 0.0
    assert not [factor for factor in finding.risk.factors if "unverified" in factor.id]
    with_marker = finding.confidence
    finding.evidence.remove(marker)
    finding.recompute_confidence()
    assert with_marker == pytest.approx(finding.confidence, abs=0.001)


def test_failed_and_successful_verification_set_the_same_field(index: SignatureIndex):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {"iss": OKTA_ISSUER, "sub": "u1"}, private, algorithm="RS256", headers={"kid": "key-1"}
    )
    jwk = json.loads(jwt.algorithms.get_default_algorithms()["RS256"].to_jwk(private.public_key()))
    jwk.update({"alg": "RS256", "use": "sig", "key_ops": ["verify"], "kid": "key-1"})
    connector = JwtConnector(ConnectorContext(index=index, config={"jwks_url": JWKS_URL}))
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk]}):
        good = connector.analyze_token(token, jwks_url=JWKS_URL)
    assert good is not None
    assert good.metadata["signature_verified"] is True
    assert good.metadata["verified"] is True
    assert "signature-unverified" not in good.tags
    bad = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1"}, jwks_url=JWKS_URL)
    assert bad.metadata["signature_verified"] is False
    assert bad.metadata["verified"] is False
    assert "signature-unverified" in bad.tags


# ------------------------------------------------- precision: decoy name suppression
# Apps that match only the generic "ai-name-hint" (a word like "agent",
# "bot", "copilot", or "bedrock" in the display name) with no real AI product
# match and only standard OIDC scopes were previously emitted as false
# positives.  They must now be suppressed.


def _okta_app(
    *,
    label: str,
    grant_types: list[str],
    app_type: str,
    scopes: list[str],
    sign_on_mode: str = "OPENID_CONNECT",
) -> dict:
    """Minimal well-formed Okta application record."""
    return {
        "id": "0oa_test_" + label[:8],
        "name": "oidc_client",
        "label": label,
        "status": "ACTIVE",
        "signOnMode": sign_on_mode,
        "created": "2025-01-01T00:00:00.000Z",
        "lastUpdated": "2025-06-01T00:00:00.000Z",
        "settings": {
            "oauthClient": {
                "application_type": app_type,
                "grant_types": grant_types,
                "redirect_uris": [],
            }
        },
        "credentials": {
            "oauthClient": {
                "client_id": "client_" + label[:8],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        },
        "_grants": [{"scopeId": s} for s in scopes],
        "_tokens": [],
    }


@pytest.mark.parametrize(
    "label",
    [
        "Jenkins Agents Admin",
        "Insurance Agent Desk",
        "Bedrock Server Panel",
        "Field Agent Portal",
        "Minecraft Bedrock Panel",
        "Copilot Money",
    ],
)
def test_okta_decoy_name_with_only_oidc_scopes_is_suppressed(run_connector, tmp_path, label: str):
    """Decoy apps whose name sounds AI-like but have only standard OIDC scopes are not reported."""
    export = tmp_path / "okta.json"
    export.write_text(
        json.dumps(
            [
                _okta_app(
                    label=label,
                    grant_types=["authorization_code", "refresh_token"],
                    app_type="web",
                    scopes=["openid", "email", "profile", "offline_access"],
                )
            ]
        )
    )
    findings, ctx = run_connector("identity.okta", input=str(export), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    assert findings == [], f"Expected no finding for decoy '{label}', got {[f.title for f in findings]}"


def test_okta_decoy_name_with_ai_scopes_is_still_reported(run_connector, tmp_path):
    """A decoy name with LLM-access scopes must still produce a finding (true positive)."""
    export = tmp_path / "okta.json"
    export.write_text(
        json.dumps(
            [
                _okta_app(
                    label="Jenkins Agents Admin",
                    grant_types=["client_credentials"],
                    app_type="service",
                    scopes=["okta.users.manage"],
                )
            ]
        )
    )
    findings, ctx = run_connector("identity.okta", input=str(export), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    # The app is a machine client with a privileged Okta scope — it should be reported.
    assert len(findings) == 1, "Expected a finding for machine client with privileged scope"
    assert findings[0].kind.name == "SERVICE_IDENTITY"


def test_okta_real_ai_app_with_oidc_scopes_still_reported(run_connector, tmp_path):
    """A recognised AI product (Fireflies, ChatGPT…) must not be suppressed even with only OIDC scopes."""
    export = tmp_path / "okta.json"
    export.write_text(
        json.dumps(
            [
                _okta_app(
                    label="Fireflies.ai Notetaker",
                    grant_types=["authorization_code", "refresh_token"],
                    app_type="web",
                    scopes=["openid", "email", "profile"],
                )
            ]
        )
    )
    findings, ctx = run_connector("identity.okta", input=str(export), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    assert findings, "Fireflies.ai should still be reported (known AI product)"
    assert "identity-app.meeting-notetakers" in findings[0].frameworks


def test_entra_decoy_name_with_only_oidc_scopes_is_suppressed(run_connector, tmp_path):
    """Entra SPs whose only AI signal is a generic name hint are not reported as false positives."""
    sp = {
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "id": "sp-decoy",
        "appId": "app-decoy",
        "displayName": "Jenkins Agents Admin",
        "servicePrincipalType": "Application",
        "accountEnabled": True,
        "createdDateTime": "2025-01-01T00:00:00Z",
        "appOwnerOrganizationId": "external-tenant",
        "publisherName": "ACME Corp",
        "signInAudience": "AzureADMultipleOrgs",
        "tags": [],
        "replyUrls": [],
        "notes": None,
    }
    # Delegated grant with only openid/profile — no AI-signal scopes.
    grant = {
        "@odata.type": "#microsoft.graph.oAuth2PermissionGrant",
        "id": "grant-decoy",
        "clientId": "sp-decoy",
        "consentType": "Principal",
        "principalId": "user-1",
        "resourceId": "graph-sp-1",
        "scope": "openid profile email offline_access",
    }
    export = tmp_path / "entra.json"
    export.write_text(json.dumps([sp, grant]))
    findings, ctx = run_connector("identity.entra", input=str(export), tenant_id="t")
    assert not ctx.stats.errors
    titles = [f.title for f in findings]
    assert not any("Jenkins" in t for t in titles), (
        f"Decoy 'Jenkins Agents Admin' should be suppressed, got: {titles}"
    )


def test_entra_decoy_name_with_privileged_scope_is_still_reported(run_connector, tmp_path):
    """An Entra SP with a decoy name but privileged Graph scope must still be reported."""
    sp = {
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "id": "sp-decoy2",
        "appId": "app-decoy2",
        "displayName": "CI Agent Panel",
        "servicePrincipalType": "Application",
        "accountEnabled": True,
        "createdDateTime": "2025-01-01T00:00:00Z",
        "appOwnerOrganizationId": "external-tenant",
        "publisherName": "ACME Corp",
        "signInAudience": "AzureADMultipleOrgs",
        "tags": [],
        "replyUrls": [],
        "notes": None,
    }
    grant = {
        "@odata.type": "#microsoft.graph.oAuth2PermissionGrant",
        "id": "grant-decoy2",
        "clientId": "sp-decoy2",
        "consentType": "AllPrincipals",
        "principalId": None,
        "resourceId": "graph-sp-1",
        "scope": "Mail.ReadWrite Files.ReadWrite.All",
    }
    export = tmp_path / "entra.json"
    export.write_text(json.dumps([sp, grant]))
    findings, ctx = run_connector("identity.entra", input=str(export), tenant_id="t")
    assert not ctx.stats.errors
    titles = [f.title for f in findings]
    assert any("CI Agent Panel" in t for t in titles), (
        f"SP with privileged scopes must still be reported, got: {titles}"
    )
