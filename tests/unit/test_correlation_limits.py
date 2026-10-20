"""Correlation size limits must preserve scoped identities and disclose omitted links."""

from __future__ import annotations

import copy
import json

import pytest

import shadowscan.correlation as correlation
from shadowscan.models import Evidence, Finding, Kind, Surface

ROLE = "arn:aws:iam::123456789012:role/AgentRole"


def _role_group(size: int) -> list[Finding]:
    role = Finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.SERVICE_IDENTITY,
        title="Role",
        resource=ROLE,
        resource_type="iam-role",
        account="123456789012",
    )
    code = [
        Finding(
            surface=Surface.CODE,
            connector="code.filesystem",
            kind=Kind.INFRA,
            title="Infrastructure reference",
            resource=f"repository-{number}/main.tf",
            resource_type="iac",
            evidence=[Evidence("iac:role", "Role reference", location=ROLE)],
        )
        for number in range(size - 1)
    ]
    return [role, *code]


@pytest.mark.parametrize("size", [25, 26])
def test_exact_role_relationship_survives_pairwise_group_boundary(size):
    group = _role_group(size)
    correlation.correlate(group)
    role = group[0]
    if size == 25:
        assert set(role.metadata["related"]) == {entry.id for entry in group[1:]}
        assert all(entry.metadata["related"] == [role.id] for entry in group[1:])
        assert all("related_truncation" not in entry.metadata for entry in group)
        return
    memberships = [entry.metadata["related_groups"][0] for entry in group]
    assert len({entry["group_id"] for entry in memberships}) == 1
    assert {entry["member_count"] for entry in memberships} == {26}
    assert memberships[0]["source_fields"] == ["resource"]
    assert all(entry["source_fields"] == ["evidence[0].location"] for entry in memberships[1:])
    assert all(entry["assurance"] == "exact-identifier" for entry in memberships)
    assert all(entry["scope"] == {"account": "123456789012", "provider": "aws"} for entry in memberships)
    assert all(entry["pairwise_expansion"] == "omitted" for entry in memberships)
    assert all("not ownership" in entry["limitation"] for entry in memberships)
    for entry in group:
        [omission] = entry.metadata["related_truncation"]
        assert omission["reason"] == "identifier-group-limit"
        assert omission["group_size"] == 26
        assert omission["pairwise_group_limit"] == 25


def test_large_exact_group_is_compact_and_never_expands_a_quadratic_clique(monkeypatch):
    original = correlation.combinations

    def bounded_combinations(values, count):
        assert len(values) <= 25
        return original(values, count)

    monkeypatch.setattr(correlation, "combinations", bounded_combinations)
    group = _role_group(2000)
    correlation.correlate(group)
    memberships = [entry.metadata["related_groups"][0] for entry in group]
    assert {entry["member_count"] for entry in memberships} == {2000}
    assert len({entry["group_id"] for entry in memberships}) == 1
    assert all(len(json.dumps(entry.metadata)) < 2000 for entry in group)
    assert all("related" not in entry.metadata for entry in group)


def _local(number: int, scope: dict[str, str], connector: str = "identity.test") -> Finding:
    return Finding(
        surface=Surface.IDENTITY,
        connector=connector,
        kind=Kind.SERVICE_IDENTITY,
        title="Client",
        resource=f"local-{number}",
        resource_type="application",
        metadata={"client_id": "shared-client-id", **scope},
    )


def test_large_local_groups_keep_conflicting_and_partial_scopes_separate():
    scopes = [
        {"tenant": "tenant-a", "workspace": "workspace-1"},
        {"tenant": "tenant-b", "workspace": "workspace-1"},
        {"tenant": "tenant-a"},
        {},
    ]
    group = [
        _local(index * 26 + number, scope, f"identity.test-{number % 2}")
        for index, scope in enumerate(scopes)
        for number in range(26)
    ]
    correlation.correlate(group)
    group_ids = []
    for index, scope in enumerate(scopes[:3]):
        entries = group[index * 26 : (index + 1) * 26]
        assert all(entry.metadata["related_groups"][0]["scope"] == scope for entry in entries)
        ids = {entry.metadata["related_groups"][0]["group_id"] for entry in entries}
        assert len(ids) == 1
        group_ids.extend(ids)
    assert len(set(group_ids)) == 3
    assert all("related_groups" not in entry.metadata for entry in group[78:])
    assert all("related" not in entry.metadata for entry in group)
    assert all("related_truncation" in entry.metadata for entry in group)
    assert all("partial scopes" in entry.metadata["related_truncation"][0]["limitation"] for entry in group)
    # The truncation token is salted per scope partition and equals that
    # partition's membership token, so per-tenant report slices cannot be
    # joined on identifier equality across conflicting scopes (#268). Members
    # outside an exact partition disclose the omission alone: no token, no
    # count that spans other scopes.
    for index in range(3):
        entries = group[index * 26 : (index + 1) * 26]
        for entry in entries:
            [omission] = entry.metadata["related_truncation"]
            assert omission["identifier_group_id"] == entry.metadata["related_groups"][0]["group_id"]
            assert omission["group_size"] == 26
    tokens = {entry.metadata["related_truncation"][0]["identifier_group_id"] for entry in group[:78]}
    assert len(tokens) == 3
    for entry in group[78:]:
        [omission] = entry.metadata["related_truncation"]
        assert "identifier_group_id" not in omission
        assert "group_size" not in omission


def test_large_entra_group_still_requires_tenant_scope():
    group = [
        _local(
            number,
            {"workspace": "shared-workspace"},
            "identity.entra" if number % 2 else "saas.microsoft-teams",
        )
        for number in range(26)
    ]
    correlation.correlate(group)
    assert all("related_groups" not in entry.metadata and "related" not in entry.metadata for entry in group)


def test_large_same_connector_group_does_not_invent_cross_surface_relations():
    group = _role_group(27)[1:]
    correlation.correlate(group)
    assert all(not any(key.startswith("related") for key in entry.metadata) for entry in group)


def test_group_metadata_is_order_independent_does_not_raise_assurance_and_clears():
    group = _role_group(26)
    before = {
        entry.id: (
            entry.kind,
            entry.confidence,
            entry.shadow,
            copy.deepcopy(entry.risk),
            entry.registry_match,
        )
        for entry in group
    }
    correlation.correlate(group)
    expected = {entry.id: copy.deepcopy(entry.metadata) for entry in group}
    correlation.correlate(list(reversed(group)))
    assert expected == {entry.id: entry.metadata for entry in group}
    assert before == {
        entry.id: (entry.kind, entry.confidence, entry.shadow, entry.risk, entry.registry_match)
        for entry in group
    }
    for entry in group:
        correlation.correlate([entry])
        assert not any(key.startswith("related") for key in entry.metadata)


def test_peer_limit_discloses_loss_on_both_endpoints_and_remains_symmetric():
    central = _local(0, {"tenant": "tenant-a", "app_id": "second-shared-id"})
    group = [central]
    for number in range(1, 41):
        entry = _local(number, {"tenant": "tenant-a"}, f"identity.test-{number}")
        if number > 20:
            entry.metadata.pop("client_id")
            entry.metadata["app_id"] = "second-shared-id"
        group.append(entry)
    correlation.correlate(group)
    peers = {entry.id: set(entry.metadata.get("related", [])) for entry in group}
    assert len(peers[central.id]) == 24
    recovered = set(peers[central.id])
    memberships: dict[str, set[str]] = {}
    for entry in group:
        for membership in entry.metadata.get("related_groups", []):
            assert membership["member_count"] == 2
            memberships.setdefault(membership["group_id"], set()).add(entry.id)
    for member_ids in memberships.values():
        assert len(member_ids) == 2
        if central.id in member_ids:
            recovered.update(member_ids - {central.id})
    assert recovered == {entry.id for entry in group[1:]}
    for entry in group:
        assert len(peers[entry.id]) <= 24
        assert all(entry.id in peers[other] for other in peers[entry.id])
        if entry is central or entry.id not in peers[central.id]:
            assert {
                "reason": "peer-limit",
                "assurance": "exact-identifier",
                "peer_limit": 24,
            } in entry.metadata["related_truncation"]
    expected = {entry.id: copy.deepcopy(entry.metadata) for entry in group}
    correlation.correlate(list(reversed(group)))
    assert expected == {entry.id: entry.metadata for entry in group}


def test_capped_partial_scope_pairs_do_not_merge_conflicting_scopes(monkeypatch):
    monkeypatch.setattr(correlation, "_MAX_CORRELATION_PEERS", 0)
    broad = _local(0, {"tenant": "tenant-a"})
    one = _local(1, {"tenant": "tenant-a", "workspace": "workspace-1"}, "identity.one")
    two = _local(2, {"tenant": "tenant-a", "workspace": "workspace-2"}, "identity.two")
    group = [broad, one, two]
    correlation.correlate(group)
    broad_ids = {member["group_id"] for member in broad.metadata["related_groups"]}
    one_ids = {member["group_id"] for member in one.metadata["related_groups"]}
    two_ids = {member["group_id"] for member in two.metadata["related_groups"]}
    assert len(broad_ids) == 2
    assert one_ids | two_ids == broad_ids
    assert not one_ids & two_ids
