"""Identity correlation must not turn shared labels into scoped resource identities."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shadowscan.config import ScanConfig
from shadowscan.correlation import correlate
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Surface

ROOT = Path(__file__).resolve().parents[2]

ARN = "arn:aws:bedrock:us-east-1:123456789012:agent/Agent-A"
SERVICE_ACCOUNT = "crew-runner@shared-ml-a.iam.gserviceaccount.com"


def finding(**kwargs) -> Finding:
    values = dict(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Discovered resource",
        resource=ARN,
        resource_type="bedrock-agent",
        provider="aws",
        account="123456789012",
        region="us-east-1",
    )
    values.update(kwargs)
    return Finding(**values)


def peer(**kwargs) -> Finding:
    return finding(surface=Surface.IDENTITY, connector="identity.test", **kwargs)


def test_fuzzy_names_only_produce_candidates_and_do_not_change_verdicts():
    left = finding(metadata={"name": "Support.Agent"}, confidence=0.7, shadow=True)
    right = peer(resource="other", metadata={"display_name": "support-agent"}, confidence=0.8, shadow=False)
    before = [
        (f.confidence, f.shadow, f.registry_match, copy.deepcopy(f.risk), copy.deepcopy(f.evidence))
        for f in (left, right)
    ]
    correlate([left, right])
    for own, other in ((left, right), (right, left)):
        assert "related" not in own.metadata
        candidate = own.metadata["related_candidates"][0]
        assert candidate["finding_id"] == other.id
        assert candidate["assurance"] == "candidate"
        assert "not proof" in candidate["limitation"]
        assert candidate["matches"][0]["key_type"] == "name"
    assert before == [(f.confidence, f.shadow, f.registry_match, f.risk, f.evidence) for f in (left, right)]


@pytest.mark.parametrize(
    "left_scope,right_scope",
    [
        # The same declared namespace with different values is a conflict.
        (
            {"connector": "identity.entra", "account": "tenant-a"},
            {"connector": "saas.microsoft-teams", "account": "tenant-b"},
        ),
        (
            {"connector": "cloud.aws", "account": "123456789012"},
            {"connector": "cloud.aws", "account": "999999999999"},
        ),
        ({"metadata": {"tenant": "tenant-a"}}, {"metadata": {"tenant_id": "tenant-b"}}),
        ({"metadata": {"workspace": "ws-a"}}, {"metadata": {"workspace_id": "ws-b"}}),
    ],
)
def test_contradictory_scope_prevents_exact_and_fuzzy_relationships(left_scope, right_scope):
    def build(factory, scope):
        values = dict(scope)
        metadata = {"name": "support-agent", "app_id": "app-0001", **values.pop("metadata", {})}
        return factory(resource="opaque-id", metadata=metadata, **values)

    left = build(finding, left_scope)
    right = build(finding, {"connector": "identity.test", "surface": Surface.IDENTITY, **right_scope})
    correlate([left, right])
    assert not any(key.startswith("related") for key in left.metadata)
    assert not any(key.startswith("related") for key in right.metadata)


@pytest.mark.parametrize(
    "left_label,right_label",
    [
        ({"provider": "entra"}, {"provider": "microsoft-teams"}),
        (
            {"provider": "aws"},
            {"provider": "bedrock-invocation-logs", "account": '{"account": "123456789012"}'},
        ),
        ({"region": "us-east-1"}, {"region": "eu-west-1"}),
    ],
)
def test_vendor_and_gateway_labels_are_not_identity_scope(left_label, right_label):
    """Provider, label-valued account and region strings differ between connectors by design."""
    principal = "arn:aws:iam::123456789012:role/AgentRole"
    left = finding(
        resource="cloudtrail:caller", metadata={"principal": principal}, **{"region": None, **left_label}
    )
    right = finding(
        connector="gateway.logs",
        surface=Surface.GATEWAY,
        resource="gateway:caller",
        metadata={"caller": principal, "name": "support-agent"},
        **{"region": None, **right_label},
    )
    left.metadata["name"] = "support-agent"
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    assert left.metadata["related_details"][0]["matches"][0]["key_type"] == "resource:aws-arn"


def test_tenant_aliases_share_scope_but_conflicting_tenants_never_match():
    left = finding(resource="opaque-id", metadata={"tenant": "tenant-a", "name": "support-agent"})
    right = peer(resource="opaque-id", metadata={"tenant_id": "tenant-b", "name": "support-agent"})
    correlate([left, right])
    assert "related" not in left.metadata and "related_candidates" not in left.metadata
    right.metadata["tenant_id"] = "tenant-a"
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    assert left.metadata["related_details"][0]["matches"][0]["scope"]["tenant"] == "tenant-a"


@pytest.mark.parametrize(
    "left_resource,right_resource",
    [
        ("resource:Service-A", "resource:service-a"),
        ("resource:service/a", "resource:service-a"),
        ("resource:service.a", "resource:service_a"),
        (ARN, ARN.lower()),
    ],
)
def test_exact_identifiers_preserve_case_and_punctuation(left_resource, right_resource):
    left, right = finding(resource=left_resource), peer(resource=right_resource)
    correlate([left, right])
    assert "related" not in left.metadata


AZURE_OPENAI = (
    "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acme-openai"
)
ROLE_ASSIGNMENT = "/subscriptions/s1/providers/Microsoft.Authorization/roleAssignments/ra1"


def test_azure_resource_ids_link_in_any_letter_case(tmp_path, run_connector):
    """ARM reports a role assignment's scope lowercased; it still names the listed resource."""
    records = [
        json.loads(line)
        for line in (ROOT / "tests" / "fixtures" / "cloud" / "azure_records.jsonl").read_text().splitlines()
    ]
    for record in records:
        if record.get("_kind") == "role-assignment":
            record["scope"] = AZURE_OPENAI.lower()
    source = tmp_path / "azure.jsonl"
    source.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    findings, _ = run_connector("cloud.azure", input=str(source))
    correlate(findings)
    by = {f.resource: f for f in findings}
    assignment, account = by[ROLE_ASSIGNMENT], by[AZURE_OPENAI]
    assert assignment.metadata["related"] == [account.id]
    [match] = assignment.metadata["related_details"][0]["matches"]
    assert match["key_type"] == "resource:azure-id"
    assert "resource" in match["target_fields"]
    assert all(field.startswith("evidence[") for field in match["source_fields"])
    assert match["scope"] == {"account": "s1", "provider": "azure"}
    # Correlation compares; it does not rewrite what each finding reported.
    assert AZURE_OPENAI.lower() in {e.location for e in assignment.evidence}
    assert account.resource == AZURE_OPENAI


@pytest.mark.parametrize("spelling", [AZURE_OPENAI.upper(), AZURE_OPENAI.lower()])
def test_azure_resource_id_casings_link_but_other_resources_do_not(spelling):
    live = finding(resource=AZURE_OPENAI, provider="azure", account="s1", region=None)
    caller = peer(resource="gateway:caller", provider=None, account=None, region=None)
    caller.metadata["resource_id"] = spelling
    correlate([live, caller])
    assert live.metadata["related"] == [caller.id]
    caller.metadata["resource_id"] = spelling.replace("ACME-OPENAI", "OTHER").replace("acme-openai", "other")
    correlate([live, caller])
    assert not any(key.startswith("related") for key in live.metadata)


def test_metadata_identifier_types_do_not_share_a_namespace():
    left = finding(resource="one", metadata={"app_id": "identity-42", "tenant": "tenant-a"})
    right = peer(resource="two", metadata={"agent_id": "identity-42", "tenant": "tenant-a"})
    correlate([left, right])
    # Different identifier types never link exactly; the shared text is at most a review hint.
    assert "related" not in left.metadata and "related_details" not in left.metadata
    right.metadata = {"app_id": "identity-42", "tenant": "tenant-a"}
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    assert left.metadata["related_details"][0]["matches"][0]["key_type"] == "metadata.app_id"


GUID = "00000000-0000-4000-8000-00000000c0de"


def _microsoft(connector: str, surface: Surface, field: str, tenant: str | None, **kwargs) -> Finding:
    return Finding(
        surface=surface,
        connector=connector,
        kind=Kind.BOT_APP,
        title=f"{connector} object",
        resource=f"{connector}:{field}",
        resource_type=field,
        provider=connector.split(".", 1)[-1],
        account=tenant,
        metadata={field: GUID, **kwargs},
    )


@pytest.mark.parametrize(
    "connector,surface,field",
    [
        ("saas.microsoft-teams", Surface.SAAS, "bot_id"),
        ("identity.entra", Surface.IDENTITY, "client_id"),
    ],
)
def test_one_entra_application_id_links_across_fields_in_the_same_tenant(connector, surface, field):
    app = _microsoft("identity.entra", Surface.CLOUD, "app_id", "tenant-a")
    other = _microsoft(connector, surface, field, "tenant-a")
    correlate([app, other])
    assert app.metadata["related"] == [other.id]
    match = app.metadata["related_details"][0]["matches"][0]
    assert match["key_type"] == "entra-application-id"
    assert match["scope"] == {"entra-tenant": "tenant-a"}
    other.account = "tenant-b"
    correlate([app, other])
    assert not any(key.startswith("related") for key in app.metadata)


def test_an_account_not_attributed_to_its_records_is_not_tenant_scope():
    """An Entra export of another tenant keeps tenant_id as account, but not as the records' tenant."""
    app = _microsoft("identity.entra", Surface.IDENTITY, "app_id", "tenant-a", account_attributed=False)
    bot = _microsoft("saas.microsoft-teams", Surface.SAAS, "bot_id", "tenant-a")
    correlate([app, bot])
    assert "related" not in app.metadata and "related" not in bot.metadata
    candidate = app.metadata["related_candidates"][0]
    assert candidate["finding_id"] == bot.id
    assert "entra-application-id" in {match["key_type"] for match in candidate["matches"]}
    app.metadata["account_attributed"] = True
    correlate([app, bot])
    assert app.metadata["related"] == [bot.id]


def test_entra_application_id_without_a_declared_tenant_is_only_a_candidate():
    """Azure reports a subscription, not a tenant, for a bot's msaAppId."""
    app = _microsoft("identity.entra", Surface.IDENTITY, "app_id", "tenant-a")
    bot = _microsoft("cloud.azure", Surface.CLOUD, "msa_app_id", "subscription-1")
    correlate([app, bot])
    assert "related" not in app.metadata
    candidate = app.metadata["related_candidates"][0]
    assert candidate["finding_id"] == bot.id
    assert "entra-application-id" in {match["key_type"] for match in candidate["matches"]}
    bot.metadata["tenant"] = "tenant-b"
    app.metadata["tenant"] = "tenant-a"
    correlate([app, bot])
    assert not any(key.startswith("related") for key in app.metadata)


def test_entra_application_fields_outside_microsoft_connectors_keep_their_own_type():
    entra = _microsoft("identity.entra", Surface.IDENTITY, "app_id", "tenant-a")
    okta = _microsoft("identity.okta", Surface.SAAS, "client_id", "tenant-a")
    correlate([entra, okta])
    assert "related" not in entra.metadata


def test_cross_tenant_name_collisions_never_link():
    entra = _microsoft(
        "identity.entra", Surface.IDENTITY, "app_id", "tenant-a", display_name="Meeting Notes AI"
    )
    teams = Finding(
        surface=Surface.SAAS,
        connector="saas.microsoft-teams",
        kind=Kind.BOT_APP,
        title="Teams app with bot: Meeting Notes AI",
        resource="teams:app:1",
        resource_type="teams-app",
        provider="microsoft-teams",
        account="tenant-b",
        metadata={"name": "Meeting Notes AI"},
    )
    correlate([entra, teams])
    assert not any(key.startswith("related") for key in entra.metadata)
    teams.account = "tenant-a"
    correlate([entra, teams])
    assert entra.metadata["related_candidates"][0]["finding_id"] == teams.id


@pytest.mark.parametrize("field", ["provider", "account", "region"])
def test_local_identifier_with_missing_scope_does_not_create_exact_edge(field):
    left = finding(resource="same-id")
    right = peer(resource="same-id", **{field: None})
    correlate([left, right])
    assert "related" not in left.metadata


def test_two_unscoped_opaque_identifiers_and_redacted_scope_cannot_create_exact_edges():
    left = finding(resource="same-id", provider=None, account=None, region=None)
    right = peer(resource="same-id", provider=None, account=None, region=None)
    correlate([left, right])
    assert "related" not in left.metadata
    left, right = finding(), peer(metadata={"tenant": "[REDACTED]"})
    correlate([left, right])
    assert "related" not in left.metadata


@pytest.mark.parametrize(
    "unusable",
    [
        {"metadata": {"workspace": "Acme [EU]"}},
        {"metadata": {"tenant": "[REDACTED]"}},
        {"metadata": {"workspace_id": " ws-1"}},
        {"connector": "identity.entra", "account": "tenant-*"},
    ],
)
def test_unusable_scope_refuses_identifier_links_but_keeps_name_candidates(unusable):
    values = dict(unusable)
    metadata = {"app_id": "app-0001", "name": "Support Agent", **values.pop("metadata", {})}
    left = finding(resource="opaque-id", metadata=metadata, **values)
    right = peer(
        resource="opaque-id", metadata={"app_id": "app-0001", "name": "support-agent", "tenant": "t-1"}
    )
    correlate([left, right])
    assert "related" not in left.metadata and "related" not in right.metadata
    [candidate] = left.metadata["related_candidates"]
    assert candidate["finding_id"] == right.id
    assert {match["key_type"] for match in candidate["matches"]} == {"name"}
    assert [entry["finding_id"] for entry in right.metadata["related_candidates"]] == [left.id]


def test_two_values_for_one_scope_still_refuse_every_link():
    left = finding(resource="opaque-id", metadata={"name": "support-agent", "tenant": "a", "tenant_id": "b"})
    right = peer(resource="opaque-id", metadata={"name": "support-agent"})
    correlate([left, right])
    assert not any(key.startswith("related") for key in left.metadata)


def test_notion_bot_in_a_bracketed_workspace_stays_a_name_candidate(tmp_path, run_connector):
    """A Notion workspace display name such as "Acme [EU]" is not an identifier to compare."""
    users = json.loads((ROOT / "tests" / "fixtures" / "saas" / "notion_users.json").read_text())
    slack = json.loads((ROOT / "tests" / "fixtures" / "saas" / "slack.json").read_text())
    [bot] = [user for user in users["results"] if user["id"] == "n2"]
    bot["name"], bot["bot"]["workspace_name"] = "Claude Assistant", "Acme [EU]"
    [app] = [
        record for record in slack if record.get("_kind") == "approved_app" and record["app"]["id"] == "A1"
    ]
    app["app"]["name"] = "Claude Assistant"
    (tmp_path / "notion.json").write_text(json.dumps(users), encoding="utf-8")
    (tmp_path / "slack.json").write_text(json.dumps(slack), encoding="utf-8")
    notion, _ = run_connector("saas.notion", input=str(tmp_path / "notion.json"))
    apps, _ = run_connector("saas.slack", input=str(tmp_path / "slack.json"))
    correlate(notion + apps)
    integration = next(f for f in notion if f.resource == "notion:bot:n2")
    slack_app = next(f for f in apps if f.resource == "slack:app:A1")
    assert integration.metadata["workspace"] == "Acme [EU]"
    assert "related" not in integration.metadata
    assert [entry["finding_id"] for entry in integration.metadata["related_candidates"]] == [slack_app.id]


@pytest.mark.parametrize(
    "resource,provider,account,region",
    [
        (ARN, "aws", "123456789012", "us-east-1"),
        ("projects/project-1/locations/europe-west1/agents/Agent-A", "gcp", "project-1", "europe-west1"),
        (
            "/subscriptions/sub-1/resourceGroups/Group-A/providers/Microsoft.Web/sites/Agent-A",
            "azure",
            "sub-1",
            "westeurope",
        ),
        ("ocid1.generativeaiagent.oc1.phx.synthetic123", "oci", "tenant-1", "us-phoenix-1"),
    ],
)
def test_global_iac_reference_links_without_code_account(resource, provider, account, region):
    live = finding(resource=resource, provider=provider, account=account, region=region)
    code = finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.INFRA,
        resource="github:acme/infra/main.tf",
        resource_type="iac",
        provider="github",
        account=None,
        region=None,
        evidence=[Evidence("iac:resource", "Cloud reference", location=resource)],
    )
    correlate([live, code])
    assert live.metadata["related"] == [code.id]
    details = live.metadata["related_details"][0]
    assert details["assurance"] == "exact-identifier"
    assert details["matches"][0]["source_fields"] == ["resource"]
    assert details["matches"][0]["target_fields"] == ["evidence[0].location"]
    assert details["matches"][0]["scope"]["provider"] == provider


def _code(connector: str, resource: str, location: str) -> Finding:
    return finding(
        surface=Surface.CODE,
        connector=connector,
        kind=Kind.INFRA,
        resource=resource,
        resource_type="iac",
        provider="github",
        account=None,
        region=None,
        evidence=[Evidence("file:langchain", "Framework import", location=location)],
    )


@pytest.mark.parametrize(
    "location",
    [
        "projects/api/src/main.py:12",
        "projects/backend/src/main.py",
        "projects/backend-api/locations/main.py:7",
        "projects/api/locations/us/agents/a",
        "projects/support-bot/agent/main.py",
    ],
)
def test_repository_paths_under_projects_are_not_gcp_resource_names(location):
    """Two monorepos with the same projects/ layout share a file path, not a GCP resource."""
    # A scan root named "projects" gives code resources the same shape.
    left = _code("code.filesystem", "projects/api/src/main.py", location)
    right = _code("code.github", "github:acme/other/projects/api/src/main.py", location)
    correlate([left, right])
    for item in (left, right):
        assert not any(key.startswith("related") for key in item.metadata)


def test_code_references_to_gcp_resource_names_still_link():
    name = "projects/project-1/locations/europe-west1/agents/Agent-A"
    live = finding(resource=name, provider="gcp", account="project-1", region="europe-west1")
    for location in (
        name,
        f"projects/project-1/serviceAccounts/{SERVICE_ACCOUNT}",
        "projects/123456/secrets/x",
    ):
        code = _code("code.filesystem", "github:acme/infra/main.tf", location)
        live.resource = location
        correlate([live, code])
        assert live.metadata["related"] == [code.id]
    # The strict form is for code: a non-code finding's GCP name parses as before.
    synthetic = "projects/acme-ml/iam/serviceAccount:runner@acme-ml.iam.gserviceaccount.com"
    left, right = finding(resource=synthetic), peer(resource=synthetic)
    correlate([left, right])
    assert left.metadata["related"] == [right.id]


def test_arn_reference_can_link_principal_to_iam_identity_but_not_wrong_account():
    left = finding(resource="arn:aws:iam::123456789012:role/AgentRole", region=None)
    right = peer(resource="cloudtrail:caller", region=None, metadata={"principal": left.resource})
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    # The ARN names its own account: a cross-account caller is the same principal.
    right.account = "999999999999"
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    right.metadata["principal"] = "arn:aws:iam::999999999999:role/AgentRole"
    correlate([left, right])
    assert "related" not in left.metadata


def test_gcp_service_account_links_to_its_caller_in_another_project(tmp_path, run_connector):
    """A Vertex AI caller in one project is the service account another project defines."""
    records = [
        {
            "_kind": "service-account",
            "_project": "shared-ml-a",
            "name": f"projects/shared-ml-a/serviceAccounts/{SERVICE_ACCOUNT}",
            "email": SERVICE_ACCOUNT,
            "displayName": "Anthropic Claude runner",
            "user_managed_keys": 0,
        },
        {
            "_kind": "audit-event",
            "_project": "ml-prod-b",
            "principal": SERVICE_ACCOUNT,
            "method": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
            "resource": "projects/ml-prod-b/locations/us-central1/publishers/google/models/gemini-1.5-pro",
            "timestamp": "2025-09-10T03:00:00Z",
            "userAgent": "google-genai-sdk/1.0",
        },
    ]
    source = tmp_path / "gcp.jsonl"
    source.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    findings, _ = run_connector("cloud.gcp", input=str(source))
    correlate(findings)
    by = {f.resource: f for f in findings}
    account = by[f"projects/shared-ml-a/serviceAccounts/{SERVICE_ACCOUNT}"]
    caller = by[f"audit:{SERVICE_ACCOUNT}"]
    assert (account.account, caller.account) == ("shared-ml-a", "ml-prod-b")
    assert caller.metadata["related"] == [account.id]
    [match] = caller.metadata["related_details"][0]["matches"]
    assert match["key_type"] == "resource:gcp-service-account"
    assert (match["source_fields"], match["target_fields"]) == (["metadata.principal"], ["resource"])
    assert match["scope"] == {"provider": "gcp"}


def _gcp(surface: Surface, project: str, resource: str, **metadata) -> Finding:
    return finding(
        surface=surface,
        connector="cloud.gcp",
        provider="gcp",
        account=project,
        resource=resource,
        metadata=metadata,
    )


@pytest.mark.parametrize(
    "spelling",
    [
        SERVICE_ACCOUNT,
        f"projects/-/serviceAccounts/{SERVICE_ACCOUNT}",
        f"projects/ml-prod-b/serviceAccounts/{SERVICE_ACCOUNT}",
    ],
)
def test_gcp_service_account_spellings_are_one_identifier_across_projects(spelling):
    defined = _gcp(Surface.IDENTITY, "shared-ml-a", f"projects/shared-ml-a/serviceAccounts/{SERVICE_ACCOUNT}")
    caller = _gcp(Surface.GATEWAY, "ml-prod-b", "audit:caller", principal=spelling)
    correlate([defined, caller])
    assert defined.metadata["related"] == [caller.id]


def test_shared_google_service_accounts_do_not_link_projects():
    """Google-managed service accounts act in many projects; sharing one is not a link."""
    principal = "cloud-logs@system.gserviceaccount.com"
    defined = _gcp(Surface.IDENTITY, "proj-alpha-1", "audit:defined", principal=principal)
    caller = _gcp(Surface.GATEWAY, "proj-beta-22", "audit:caller", principal=principal)
    correlate([defined, caller])
    for item in (defined, caller):
        assert "related" not in item.metadata


@pytest.mark.parametrize(
    "other",
    [
        # Not Google-issued service account addresses: local identifiers, and
        # the declared project conflict blocks them like any other.
        "crew-runner@shared-ml-a.iam.gserviceaccount.com.example.com",
        "crew-runner@example-gserviceaccount.com",
        "crew-runner@gserviceaccount.com",
        "Crew-Runner@shared-ml-a.iam.gserviceaccount.com",
        "crew-runner@acme.com",
    ],
)
def test_lookalike_service_account_addresses_keep_their_project_scope(other):
    defined = _gcp(Surface.IDENTITY, "shared-ml-a", "audit:defined", principal=other)
    caller = _gcp(Surface.GATEWAY, "ml-prod-b", "audit:caller", principal=other)
    correlate([defined, caller])
    assert not any(key.startswith("related") for key in defined.metadata)
    caller.metadata["principal"] = SERVICE_ACCOUNT
    caller.account = "shared-ml-a"
    correlate([defined, caller])
    assert "related" not in defined.metadata


@pytest.mark.parametrize(
    "bad",
    [
        "[REDACTED]",
        " bad-id",
        "arn:aws:bedrock:*:*:agent/Agent-A",
        "arn:aws:bedrock:us-east-1::agent/Agent-A",
    ],
)
def test_unusable_identities_never_establish_exact_relationships(bad):
    left, right = finding(resource=bad), peer(resource=bad)
    correlate([left, right])
    assert "related" not in left.metadata


@pytest.mark.parametrize(
    "shared",
    [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0",
    ],
)
def test_shared_aws_catalog_arns_never_relate_findings(shared):
    # Two accounts attaching the same managed policy or calling the same
    # foundation model are not one identity, exactly or as a candidate.
    left = finding(account="111111111111", metadata={"arn": shared})
    right = peer(resource="cloudtrail:caller", account="222222222222", metadata={"arn": shared})
    correlate([left, right])
    for item in (left, right):
        assert not {"related", "related_details", "related_candidates"} & set(item.metadata)


def test_globally_unique_accountless_arns_still_link():
    bucket = "arn:aws:s3:::shared-agent-artifacts"
    left = finding(account="111111111111", metadata={"arn": bucket})
    right = peer(resource="cloudtrail:caller", account="222222222222", metadata={"arn": bucket})
    correlate([left, right])
    assert left.metadata["related"] == [right.id]


@pytest.mark.parametrize("field", ["resource", "principal", "client_id", "account"])
@pytest.mark.parametrize("pattern", ["*", "svc-*", "svc-?", "svc-[ab]"])
def test_wildcards_in_local_identifiers_or_scope_never_create_exact_relationships(field, pattern):
    left, right = finding(resource="one"), peer(resource="two")
    for item in (left, right):
        if field in {"resource", "account"}:
            setattr(item, field, pattern)
        else:
            item.metadata[field] = pattern
        if field == "account":
            item.metadata["client_id"] = "same-client"
    correlate([left, right])
    assert "related" not in left.metadata


def test_stale_relationships_rebuilt_even_when_current_scan_has_no_matches():
    left, right = finding(), peer()
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    left.metadata["related_candidates"] = [{"finding_id": "stale-id"}]
    correlate([left])
    assert not any(key.startswith("related") for key in left.metadata)


def test_same_connector_observations_do_not_link_and_exact_suppresses_duplicate_candidate():
    left, right = finding(), finding(resource_type="second-observation")
    correlate([left, right])
    assert "related" not in left.metadata
    right.connector = "identity.test"
    left.metadata["name"] = right.metadata["name"] = "shared-name"
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    assert "related_candidates" not in left.metadata


def test_large_ambiguous_name_group_is_bounded_and_order_independent():
    group = [
        finding(resource=f"resource-{n}", connector=f"test.{n}", metadata={"name": "shared-name"})
        for n in range(26)
    ]
    correlate(group)
    assert all("related_candidates" not in f.metadata for f in group)
    group.pop()
    correlate(group)
    expected = {f.id: copy.deepcopy(f.metadata) for f in group}
    assert all(len(f.metadata["related_candidates"]) == 24 for f in group)
    correlate(list(reversed(group)))
    assert expected == {f.id: f.metadata for f in group}


def test_multiple_name_groups_cannot_create_unbounded_or_asymmetric_peer_lists():
    central = finding(metadata={"name": "group-name", "app_slug": "group-slug"})
    group = [central]
    group.extend(
        finding(
            resource=f"resource-{n}",
            connector=f"test.{n}",
            metadata={"name": "group-name" if n < 20 else "group-slug"},
        )
        for n in range(40)
    )
    correlate(group)
    peers = {f.id: {entry["finding_id"] for entry in f.metadata.get("related_candidates", [])} for f in group}
    assert len(peers[central.id]) == 24
    for fid, linked in peers.items():
        assert len(linked) <= 24
        assert all(fid in peers[other] for other in linked)


def _pairs(findings, field):
    by_id = {f.id: f for f in findings}
    pairs = set()
    for f in findings:
        entries = f.metadata.get(field, [])
        ids = entries if field == "related" else [entry["finding_id"] for entry in entries]
        for other in ids:
            pairs.add(
                tuple(sorted([(f.connector, f.resource), (by_id[other].connector, by_id[other].resource)]))
            )
    return pairs


def test_offline_demo_keeps_every_cross_surface_link(index):
    """The bundled demo keeps the six links of the fuzzy-name model: three exact, three for review."""
    result = Engine(ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml"), index).run()
    exact = _pairs(result.findings, "related")
    candidates = _pairs(result.findings, "related_candidates")
    bob = "arn:aws:iam::123456789012:user/bob"
    role = "arn:aws:sts::123456789012:assumed-role/ops-agent-role/i-0abc"
    openai = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acme-openai"
    assert {
        (("cloud.aws", f"cloudtrail:{bob}"), ("gateway.logs", f"aws:{bob}")),
        (("cloud.aws", f"cloudtrail:{role}"), ("gateway.logs", f"aws:{role}")),
        (
            ("cloud.azure", "/subscriptions/s1/providers/Microsoft.Authorization/roleAssignments/ra1"),
            ("cloud.azure", openai),
        ),
    } <= exact
    # Every other exact link is the same fully qualified ARN seen by two findings.
    for f in result.findings:
        for detail in f.metadata.get("related_details", []):
            assert {match["key_type"] for match in detail["matches"]} <= {
                "resource:aws-arn",
                "resource:azure-id",
            }
    # Name and caller-label matches main linked directly are kept as review candidates.
    assert candidates == {
        (("gateway.logs", "azure:obj-1"), ("identity.entra", "entra:app:app-agent")),
        (("gateway.logs", "azure:obj-1"), ("identity.entra", "entra:sp:sp-2")),
        (("identity.entra", "entra:sp:sp-1"), ("saas.microsoft-teams", "teams:app:ta2")),
    }
