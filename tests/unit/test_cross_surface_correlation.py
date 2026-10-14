"""Identity correlation must not turn shared labels into scoped resource identities."""

from __future__ import annotations

import copy

import pytest

from shadowscan.correlation import correlate
from shadowscan.models import Evidence, Finding, Kind, Surface

ARN = "arn:aws:bedrock:us-east-1:123456789012:agent/Agent-A"


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
    "field,left_value,right_value",
    [
        ("account", "123456789012", "999999999999"),
        ("provider", "aws", "azure"),
        ("region", "us-east-1", "eu-west-1"),
    ],
)
def test_contradictory_scope_prevents_exact_and_fuzzy_relationships(field, left_value, right_value):
    left = finding(resource="opaque-id", metadata={"name": "support-agent"}, **{field: left_value})
    right = peer(resource="opaque-id", metadata={"name": "support-agent"}, **{field: right_value})
    correlate([left, right])
    assert "related" not in left.metadata
    assert "related_candidates" not in left.metadata


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


def test_metadata_identifier_types_do_not_share_a_namespace():
    left = finding(resource="one", metadata={"app_id": "identity-42"})
    right = peer(resource="two", metadata={"agent_id": "identity-42"})
    correlate([left, right])
    assert not any(key.startswith("related") for key in left.metadata)
    right.metadata = {"app_id": "identity-42"}
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    assert left.metadata["related_details"][0]["matches"][0]["key_type"] == "metadata.app_id"


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


def test_arn_reference_can_link_principal_to_iam_identity_but_not_wrong_account():
    left = finding(resource="arn:aws:iam::123456789012:role/AgentRole", region=None)
    right = peer(resource="cloudtrail:caller", region=None, metadata={"principal": left.resource})
    correlate([left, right])
    assert left.metadata["related"] == [right.id]
    right.account = "999999999999"
    correlate([left, right])
    assert "related" not in left.metadata


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
