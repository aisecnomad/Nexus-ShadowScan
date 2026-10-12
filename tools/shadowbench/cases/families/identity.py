"""Identity-surface families: Okta applications and Entra service principals.

Rubric. An identity is ``agent`` when the export shows delegated or autonomous
machine operation by AI: a non-human client configured for OAuth token
exchange (on-behalf-of delegation, the pattern agent frameworks use), an Entra
Agent ID object, an app registration created for a Copilot Studio agent, or an
OAuth client published by a vendor whose product is an AI agent platform. It is
``llm`` when the client belongs to an AI SaaS vendor whose product is not
agentic (chat, transcription). It is ``none`` otherwise, including non-human
service clients without delegation or AI evidence and apps whose names merely
contain ``agent``, ``copilot``, ``bedrock`` or ``mcp``.
"""

from __future__ import annotations

from typing import Any

from tools.benchmark.common import Rand
from tools.shadowbench.cases.contract import TruthEntity
from tools.shadowbench.cases.families import Draft, email, guid, iso

AGENT_VENDORS = (
    ("Zapier Agents", "zapier.com", "Zapier Inc."),
    ("Glean Agents", "glean.com", "Glean Technologies"),
    ("Salesforce Agentforce", "salesforce.com", "Salesforce, Inc."),
    ("Microsoft Copilot Studio", "copilotstudio.microsoft.com", "Microsoft Corporation"),
    ("Relevance AI", "relevanceai.com", "Relevance AI Pty Ltd"),
    ("Lindy", "lindy.ai", "Lindy AI Inc."),
    ("Devin", "devin.ai", "Cognition AI"),
    ("Sierra", "sierra.ai", "Sierra Technologies"),
)
LLM_VENDORS = (
    ("ChatGPT Enterprise", "chatgpt.com", "OpenAI, L.L.C."),
    ("Claude", "claude.ai", "Anthropic PBC"),
    ("Otter.ai", "otter.ai", "AISense Inc."),
    ("Fireflies.ai", "fireflies.ai", "Fireflies.ai Corp."),
    ("Perplexity", "perplexity.ai", "Perplexity AI"),
    ("Read.ai", "read.ai", "Read AI, Inc."),
    ("Grammarly", "grammarly.com", "Grammarly, Inc."),
)
PLAIN_VENDORS = (
    ("Workday", "workday.com", "Workday, Inc."),
    ("Zoom", "zoom.us", "Zoom Video Communications"),
    ("Salesforce", "salesforce.com", "Salesforce, Inc."),
    ("Slack", "slack.com", "Slack Technologies"),
    ("Datadog", "datadoghq.com", "Datadog, Inc."),
    ("GitHub", "github.com", "GitHub, Inc."),
    ("Jira Cloud", "atlassian.net", "Atlassian"),
    ("Expensify", "expensify.com", "Expensify, Inc."),
)
DECOY_NAMES = (
    ("Field Agent Portal", "fieldops.acme.example", "field-service dispatch for human agents"),
    ("Insurance Agent Desk", "agentdesk.acme.example", "broker portal"),
    ("Jenkins Agents Admin", "ci.acme.example", "CI build agents"),
    ("Bedrock Server Panel", "mc.acme.example", "Minecraft Bedrock server panel"),
    ("Copilot Money", "copilot.money", "personal finance app"),
    ("MCP Partner Center", "partner.microsoft.com", "Microsoft Cloud Partner program"),
)
SERVICE_PLAIN = (
    ("terraform-okta", "okta.groups.manage,okta.users.read", "Terraform provider for Okta"),
    ("scim-provisioner", "okta.users.manage", "HR SCIM sync"),
    ("backup-exporter", "okta.logs.read", "SIEM log export"),
    ("grafana-sso-sync", "okta.groups.read", "Grafana team sync"),
)
AGENT_SERVICE_NAMES = (
    "svc-orchestrator",
    "support-automation",
    "procurement-runner",
    "ops-copilot-svc",
    "ticket-triage",
)


def okta_id(rd: Rand) -> str:
    return "0oa" + "".join(rd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(17))


def _oidc_app(
    rd: Rand, label: str, homepage: str, app_type: str, grants: list[str], auth: str
) -> dict[str, Any]:
    app_id = okta_id(rd)
    return {
        "id": app_id,
        "name": "oidc_client",
        "label": label,
        "status": "ACTIVE",
        "created": iso(rd, 2025),
        "lastUpdated": iso(rd),
        "signOnMode": "OPENID_CONNECT",
        "settings": {
            "oauthClient": {
                "application_type": app_type,
                "grant_types": grants,
                "response_types": ["code"] if "authorization_code" in grants else [],
                "redirect_uris": [f"https://{homepage}/oauth/okta/callback"] if app_type == "web" else [],
                "consent_method": "REQUIRED" if app_type == "web" else "TRUSTED",
            }
        },
        "credentials": {"oauthClient": {"client_id": app_id, "token_endpoint_auth_method": auth}},
        "_links": {"self": {"href": f"https://acme.okta.com/api/v1/apps/{app_id}"}},
    }


def _saml_app(rd: Rand, label: str, homepage: str) -> dict[str, Any]:
    app_id = okta_id(rd)
    return {
        "id": app_id,
        "name": "template_saml_2_0" if rd.chance(0.7) else "bookmark",
        "label": label,
        "status": "ACTIVE",
        "created": iso(rd, 2024),
        "lastUpdated": iso(rd, 2025),
        "signOnMode": "SAML_2_0" if rd.chance(0.7) else "BOOKMARK",
        "settings": {"app": {"audienceRestriction": f"https://{homepage}/saml", "requestCompressed": False}},
        "_links": {"self": {"href": f"https://acme.okta.com/api/v1/apps/{app_id}"}},
    }


def _grants(rd: Rand, app_id: str, scopes: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "id": "oag" + rd.hexid(17),
            "status": "ACTIVE",
            "created": iso(rd, 2025),
            "issuer": "https://acme.okta.com",
            "clientId": app_id,
            "scopeId": s,
            "source": "ADMIN",
        }
        for s in scopes
    ]


def _tokens(rd: Rand, app_id: str, scopes: list[str], n: int) -> list[dict[str, Any]]:
    return [
        {
            "id": "oar" + rd.hexid(17),
            "status": "ACTIVE",
            "created": iso(rd),
            "clientId": app_id,
            "userId": "00u" + rd.hexid(17),
            "scopes": scopes,
            "issuer": "https://acme.okta.com",
        }
        for _ in range(n)
    ]


# --- Okta families ---------------------------------------------------------


def okta_service_token_exchange(rd: Rand) -> Draft:
    """A service client with token-exchange delegation and admin scopes: an agent identity."""
    label = str(rd.choice(AGENT_SERVICE_NAMES)) + ("-" + rd.hexid(3) if rd.chance(0.5) else "")
    app = _oidc_app(
        rd,
        label,
        "internal",
        "service",
        ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "private_key_jwt",
    )
    scopes = rd.sample(["okta.users.read", "okta.groups.manage", "okta.apps.read", "okta.logs.read"], 2)
    return Draft(
        "okta-service-token-exchange",
        "agent",
        "medium",
        "Service client with OAuth token exchange (delegated on-behalf-of) and admin API scopes.",
        {"apps": [app], f"grants/{app['id']}": _grants(rd, app["id"], scopes)},
        expected=[
            TruthEntity(
                "app",
                f"app:{app['id']}",
                "agent",
                {"platform": "okta", "label": label},
                "grant_types include urn:ietf:params:oauth:grant-type:token-exchange on a service client",
            )
        ],
    )


def okta_agent_saas(rd: Rand) -> Draft:
    name, domain, _vendor = rd.choice(AGENT_VENDORS)
    app = _oidc_app(rd, name, domain, "web", ["authorization_code", "refresh_token"], "client_secret_basic")
    scopes = ["openid", "email", "profile", "okta.users.read"]
    n = rd.randint(1, 12)
    return Draft(
        "okta-agent-saas",
        "agent",
        "easy",
        f"OIDC client for {name}, an AI agent platform, with user consents.",
        {"apps": [app], f"tokens/{app['id']}": _tokens(rd, app["id"], scopes, n)},
        expected=[
            TruthEntity(
                "app",
                f"app:{app['id']}",
                "agent",
                {"platform": "okta", "label": name, "vendor_domain": domain},
                f"redirect_uris on {domain}: the vendor's product is an AI agent platform",
            )
        ],
    )


def okta_llm_saas(rd: Rand) -> Draft:
    name, domain, _vendor = rd.choice(LLM_VENDORS)
    app = _oidc_app(rd, name, domain, "web", ["authorization_code", "refresh_token"], "client_secret_basic")
    scopes = ["openid", "email", "profile"] + (["okta.users.read"] if rd.chance(0.3) else [])
    return Draft(
        "okta-llm-saas",
        "llm",
        "easy",
        f"OIDC client for {name}, an AI SaaS product without agentic action.",
        {"apps": [app], f"tokens/{app['id']}": _tokens(rd, app["id"], scopes, rd.randint(1, 40))},
        expected=[
            TruthEntity(
                "app",
                f"app:{app['id']}",
                "llm",
                {"platform": "okta", "label": name, "vendor_domain": domain},
                f"redirect_uris on {domain}: AI SaaS vendor, chat or transcription product",
            )
        ],
    )


def okta_plain_saas(rd: Rand) -> Draft:
    name, domain, _vendor = rd.choice(PLAIN_VENDORS)
    app = _saml_app(rd, name, domain)
    return Draft("okta-plain-saas", "none", "easy", f"SAML or bookmark app for {name}.", {"apps": [app]})


def okta_decoy_name(rd: Rand) -> Draft:
    name, domain, what = rd.choice(DECOY_NAMES)
    app = _saml_app(rd, name, domain)
    return Draft("okta-decoy-name", "none", "hard", f"{what}; the name only sounds like AI.", {"apps": [app]})


def okta_service_plain(rd: Rand) -> Draft:
    label, scopes, what = rd.choice(SERVICE_PLAIN)
    app = _oidc_app(rd, label, "internal", "service", ["client_credentials"], "private_key_jwt")
    return Draft(
        "okta-service-plain",
        "none",
        "hard",
        f"Service client for {what}: machine identity without delegation or AI evidence.",
        {"apps": [app], f"grants/{app['id']}": _grants(rd, app["id"], scopes.split(","))},
    )


OKTA_AGENT = (okta_service_token_exchange, okta_agent_saas)
OKTA_LLM = (okta_llm_saas,)
OKTA_NONE = (okta_plain_saas, okta_decoy_name, okta_service_plain)


# --- Entra families --------------------------------------------------------

GRAPH = "00000003-0000-0000-c000-000000000000"
ROLE_IDS = {
    "Mail.Read": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
    "Mail.ReadWrite": "e2a3a72e-5f79-4c64-b1b1-878b674ecb07",
    "Mail.Send": "b633e1c5-b582-4048-a93e-9f11b44c7e96",
    "Files.ReadWrite.All": "75359482-048d-4d94-b6cb-4a7ba79f1c5e",
    "Files.Read.All": "01d4889c-1287-42c6-ac1f-5d1e02578ef6",
    "Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "Sites.ReadWrite.All": "9492366f-7969-46a4-8d15-ed1a20078fff",
    "Calendars.Read": "798ee544-9d2d-430c-a058-570e29e34338",
}


def _sp(rd: Rand, name: str, kind: str, publisher: str | None, **extra: Any) -> dict[str, Any]:
    app_id = guid(rd)
    sp: dict[str, Any] = {
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "id": guid(rd),
        "appId": app_id,
        "displayName": name,
        "servicePrincipalType": kind,
        "accountEnabled": True,
        "createdDateTime": iso(rd, 2025),
        "appOwnerOrganizationId": extra.pop("owner", "72f988bf-0000-4000-8000-" + rd.hexid(12)),
        "publisherName": publisher,
        "signInAudience": "AzureADMultipleOrgs" if publisher else "AzureADMyOrg",
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
        "replyUrls": [],
        "notes": None,
    }
    sp.update(extra)
    return sp


def _grant(rd: Rand, sp_id: str, scopes: str, all_principals: bool) -> dict[str, Any]:
    return {
        "@odata.type": "#microsoft.graph.oAuth2PermissionGrant",
        "id": rd.hexid(40),
        "clientId": sp_id,
        "consentType": "AllPrincipals" if all_principals else "Principal",
        "principalId": None if all_principals else guid(rd),
        "resourceId": "graph-sp-" + rd.hexid(8),
        "scope": scopes,
    }


def _role_assignment(rd: Rand, sp_id: str, role: str) -> dict[str, Any]:
    return {
        "@odata.type": "#microsoft.graph.appRoleAssignment",
        "id": rd.hexid(32),
        "appRoleId": ROLE_IDS[role],
        "principalId": sp_id,
        "principalType": "ServicePrincipal",
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": "graph-sp-" + rd.hexid(8),
        "createdDateTime": iso(rd),
    }


def _application(rd: Rand, sp: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    return {
        "@odata.type": "#microsoft.graph.application",
        "id": guid(rd),
        "appId": sp["appId"],
        "displayName": sp["displayName"],
        "createdDateTime": sp["createdDateTime"],
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [
            {"resourceAppId": GRAPH, "resourceAccess": [{"id": ROLE_IDS[r], "type": "Role"} for r in roles]}
        ],
        "passwordCredentials": [{"displayName": "runner", "endDateTime": "2027-01-01T00:00:00Z"}],
    }


def _entra_draft(
    family: str,
    label: str,
    difficulty: str,
    rationale: str,
    sp: dict[str, Any],
    evidence: str,
    **records: Any,
) -> Draft:
    expected = (
        [
            TruthEntity(
                "app",
                f"app:{sp['appId']}",
                label,
                {"platform": "entra", "label": sp["displayName"]},
                evidence,
            )
        ]
        if label != "none"
        else []
    )
    recs: dict[str, list[dict[str, Any]]] = {"servicePrincipals": [sp]}
    for key, value in records.items():
        recs[key] = list(value)
    return Draft(family, label, difficulty, rationale, recs, expected=expected)


def entra_app_only_agent(rd: Rand) -> Draft:
    """An app registration with app-only Graph roles whose description states its agent framework."""
    framework = rd.choice(("LangGraph", "CrewAI", "Semantic Kernel", "AutoGen", "OpenAI Agents SDK"))
    task = rd.choice(("supplier negotiation", "ticket triage", "invoice matching", "incident response"))
    name = rd.choice(("procurement-runner", "support-triage-svc", "finance-ops-bot", "sre-responder"))
    sp = _sp(
        rd,
        name,
        "Application",
        None,
        owner="acme-tenant",
        notes=f"{framework} agent for {task}; runs unattended from AKS",
        description=f"Autonomous {task} agent ({framework})",
    )
    roles = rd.sample(
        ["Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.ReadWrite.All", "User.Read.All"], 2
    )
    return _entra_draft(
        "entra-app-only-agent",
        "agent",
        "medium",
        "Tenant app registration with application permissions and a description naming an agent framework.",
        sp,
        f"notes/description name {framework} agent; appRoleAssignments grant app-only {', '.join(roles)}",
        applications=[_application(rd, sp, roles)],
        appRoleAssignments=[_role_assignment(rd, sp["id"], r) for r in roles],
    )


def entra_agent_identity(rd: Rand) -> Draft:
    """A Microsoft Entra Agent ID identity bound to a blueprint."""
    name = rd.choice(("HR Benefits Agent", "Expense Audit Agent", "Onboarding Agent", "Deal Desk Agent"))
    sp = _sp(rd, name, "Application", None, owner="acme-tenant")
    sp["agentIdentityBlueprintId"] = guid(rd)
    sp["servicePrincipalType"] = "Application"
    sp["tags"] = ["AgentIdentity"]
    return _entra_draft(
        "entra-agent-identity",
        "agent",
        "easy",
        "Entra Agent ID object: a service principal carrying agentIdentityBlueprintId.",
        sp,
        "agentIdentityBlueprintId present: the object is an Entra agent identity",
    )


def entra_copilot_studio_sp(rd: Rand) -> Draft:
    name = rd.choice(("IT Helpdesk Agent", "Policy Q&A Agent", "Sales Enablement Agent"))
    sp = _sp(rd, f"{name} (Copilot Studio)", "Application", None, owner="acme-tenant")
    sp["replyUrls"] = ["https://token.botframework.com/.auth/web/redirect"]
    sp["homepage"] = "https://copilotstudio.microsoft.com/environments/Default-acme/bots/" + rd.hexid(12)
    sp["tags"] = ["WindowsAzureActiveDirectoryIntegratedApp", "copilot-studio"]
    grants = [_grant(rd, sp["id"], "User.Read Sites.Read.All Mail.Read", True)]
    return _entra_draft(
        "entra-copilot-studio-sp",
        "agent",
        "medium",
        "App registration created for a published Copilot Studio agent with tenant-wide consent.",
        sp,
        "homepage under copilotstudio.microsoft.com and Bot Framework redirect URI; AllPrincipals grant",
        oauth2PermissionGrants=grants,
    )


def entra_agent_saas(rd: Rand) -> Draft:
    name, domain, vendor = rd.choice(AGENT_VENDORS)
    sp = _sp(rd, name, "Application", vendor, homepage=f"https://{domain}")
    sp["replyUrls"] = [f"https://{domain}/auth/microsoft/callback"]
    sp["verifiedPublisher"] = {"displayName": vendor, "verifiedPublisherId": rd.hexid(8)}
    scopes = "User.Read Mail.ReadWrite Files.ReadWrite.All offline_access"
    return _entra_draft(
        "entra-agent-saas",
        "agent",
        "easy",
        f"Multi-tenant service principal for {name} with delegated write scopes.",
        sp,
        f"publisher {vendor} ({domain}): AI agent platform; delegated Mail.ReadWrite and Files.ReadWrite.All",
        oauth2PermissionGrants=[_grant(rd, sp["id"], scopes, rd.chance(0.5))],
    )


def entra_llm_saas(rd: Rand) -> Draft:
    name, domain, vendor = rd.choice(LLM_VENDORS)
    sp = _sp(rd, name, "Application", vendor, homepage=f"https://{domain}")
    sp["replyUrls"] = [f"https://{domain}/auth/microsoft/callback"]
    scopes = rd.choice(
        ("User.Read offline_access", "User.Read Calendars.Read OnlineMeetings.Read", "User.Read email")
    )
    return _entra_draft(
        "entra-llm-saas",
        "llm",
        "easy",
        f"Service principal for {name}, an AI SaaS product without agentic action.",
        sp,
        f"publisher {vendor} ({domain}): AI chat or transcription product; delegated read scopes",
        oauth2PermissionGrants=[_grant(rd, sp["id"], scopes, False) for _ in range(rd.randint(1, 3))],
    )


def entra_sso_plain(rd: Rand) -> Draft:
    name, domain, vendor = rd.choice(PLAIN_VENDORS)
    sp = _sp(rd, name, "Application", vendor, homepage=f"https://{domain}")
    sp["replyUrls"] = [f"https://{domain}/saml/acs"]
    sp["preferredSingleSignOnMode"] = "saml"
    return _entra_draft("entra-sso-plain", "none", "easy", f"SAML SSO service principal for {name}.", sp, "")


def entra_managed_identity_decoy(rd: Rand) -> Draft:
    name = rd.choice(
        ("aks-agent-runner", "vm-datadog-agent", "copilot-ingest-mi", "bedrock-backup-mi", "mcp-sync-mi")
    )
    sp = _sp(rd, name, "ManagedIdentity", None, owner="acme-tenant")
    sp["alternativeNames"] = ["isExplicit=True", "/subscriptions/" + guid(rd) + "/resourcegroups/rg-platform"]
    sp["tags"] = []
    return _entra_draft(
        "entra-managed-identity-decoy",
        "none",
        "hard",
        "Managed identity whose name contains an AI-sounding word; no roles, grants or AI evidence.",
        sp,
        "",
    )


def entra_service_app_plain(rd: Rand) -> Draft:
    name, role, what = rd.choice(
        (
            ("Okta SCIM Provisioning", "User.Read.All", "SCIM user sync"),
            ("Backup Exporter", "Files.Read.All", "SharePoint backup"),
            ("Directory Audit Collector", "Directory.Read.All", "SIEM directory export"),
        )
    )
    sp = _sp(rd, name, "Application", None, owner="acme-tenant", notes=what)
    return _entra_draft(
        "entra-service-app-plain",
        "none",
        "hard",
        f"Tenant app with app-only {role} for {what}: machine identity without AI evidence.",
        sp,
        "",
        applications=[_application(rd, sp, [role])],
        appRoleAssignments=[_role_assignment(rd, sp["id"], role)],
    )


def entra_decoy_name(rd: Rand) -> Draft:
    name, domain, what = rd.choice(DECOY_NAMES)
    sp = _sp(rd, name, "Application", None, homepage=f"https://{domain}")
    sp["preferredSingleSignOnMode"] = "saml"
    return _entra_draft("entra-decoy-name", "none", "hard", f"{what}; the name only sounds like AI.", sp, "")


ENTRA_AGENT = (entra_app_only_agent, entra_agent_identity, entra_copilot_studio_sp, entra_agent_saas)
ENTRA_LLM = (entra_llm_saas,)
ENTRA_NONE = (entra_sso_plain, entra_managed_identity_decoy, entra_service_app_plain, entra_decoy_name)

ROLE_MAP = {"@odata.type": "#roleMap", "roles": {v: k for k, v in ROLE_IDS.items()}}


def emails_for(rd: Rand, n: int) -> list[str]:
    return [email(rd) for _ in range(n)]
