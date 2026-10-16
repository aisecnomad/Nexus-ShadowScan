"""Tenant identity and malformed provider data must survive complete scan gates."""

from __future__ import annotations

import copy
import json
from unittest.mock import Mock

import pytest
import yaml

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.connectors.saas.teams import TeamsConnector
from shadowscan.engine import Engine
from shadowscan.merge import merge
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry, card_stub_for

SLACK_APP = {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []}
TEAMS_APP = {
    "_kind": "teamsApp",
    "id": "valid-app",
    "distributionMethod": "organization",
    "displayName": "ChatGPT",
}
ATLASSIAN_SITE = "https://approved.atlassian.net"
OTHER_ATLASSIAN_SITE = "https://different.atlassian.net"


def scan(tmp_path, connector, records, *, index=None, **settings):
    """Run one connector over ``records``; pass ``index`` when the test patches the index it uses."""
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    return Engine(
        ScanConfig(connectors=[ConnectorSpec(connector, {"input": str(source), **settings})], parallel=1),
        index,
    ).run()


def atlassian_scan(fixtures, *, site=None, inventory=()):
    config = {"input": str(fixtures / "saas" / "atlassian_shared_app.json")}
    if site is not None:
        config["site"] = site
    return Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.atlassian", config)], inventory=list(inventory))
    ).run()


def test_atlassian_missing_site_preserves_nonapprovable_evidence(fixtures, tmp_path):
    report = atlassian_scan(fixtures)
    assert not report.complete and len(report.findings) == 1
    assert any("site identity is unresolved" in warning for warning in report.stats[0].warnings)
    finding = report.findings[0]
    assert finding.account is None and finding.metadata["identity_unresolved"] is True
    card = card_stub_for(finding)
    assert card["discovery"]["resources"] == []
    assert card["discovery"]["accounts"] == []
    broad = Inventory(
        [InventoryEntry(agent_id="broad", resources=["*"], accounts=[ATLASSIAN_SITE, OTHER_ATLASSIAN_SITE])]
    )
    candidate = Finding.from_dict(finding.to_dict())
    assert broad.match(candidate) is None
    assert candidate.metadata["registry_match_reason"] == "missing-atlassian-account-scope"
    path = tmp_path / "unbound.yaml"
    path.write_text(yaml.safe_dump(card), encoding="utf-8")
    for site in (ATLASSIAN_SITE, OTHER_ATLASSIAN_SITE):
        assert atlassian_scan(fixtures, site=site, inventory=[str(path)]).findings[0].shadow


def test_atlassian_missing_site_empty_export_is_incomplete(tmp_path):
    report = scan(tmp_path, "saas.atlassian", [])
    assert not report.complete and not report.findings
    assert any("site identity is unresolved" in warning for warning in report.stats[0].warnings)


def test_atlassian_scoped_card_approves_only_its_own_site(fixtures, tmp_path):
    first = atlassian_scan(fixtures, site=ATLASSIAN_SITE)
    second = atlassian_scan(fixtures, site=OTHER_ATLASSIAN_SITE)
    assert first.complete and second.complete
    one, two = first.findings[0], second.findings[0]
    assert one.resource == two.resource and one.id != two.id
    assert len(merge([one, two])) == 2
    card = card_stub_for(one)
    assert card["discovery"]["accounts"] == [ATLASSIAN_SITE]
    assert card["discovery"]["resources"] == [one.resource]
    path = tmp_path / "approved.yaml"
    path.write_text(yaml.safe_dump(card), encoding="utf-8")
    assert not atlassian_scan(fixtures, site=ATLASSIAN_SITE, inventory=[str(path)]).findings[0].shadow
    assert atlassian_scan(fixtures, site=OTHER_ATLASSIAN_SITE, inventory=[str(path)]).findings[0].shadow
    # Older generated cards must not acquire tenant-wide authority now that
    # the connector learns each installation's trusted site.
    historical = Inventory([InventoryEntry(agent_id="historical", resources=[one.resource])])
    assert historical.match(one) is None and historical.match(two) is None
    explicit = Inventory(
        [
            InventoryEntry(
                agent_id="reviewed", resources=[one.resource], accounts=[ATLASSIAN_SITE, OTHER_ATLASSIAN_SITE]
            )
        ]
    )
    assert explicit.match(one) is not None and explicit.match(two) is not None


def test_atlassian_site_origin_is_canonical_but_app_id_is_case_sensitive(fixtures):
    report = atlassian_scan(fixtures, site="HTTPS://APPROVED.ATLASSIAN.NET:443/")
    assert report.complete
    finding = report.findings[0]
    assert finding.account == ATLASSIAN_SITE
    assert card_stub_for(finding)["discovery"]["accounts"] == [ATLASSIAN_SITE]
    inventory = Inventory(
        [
            InventoryEntry(
                agent_id="reviewed",
                resources=[finding.resource],
                accounts=["HTTPS://APPROVED.ATLASSIAN.NET:443/"],
            )
        ]
    )
    assert inventory.match(finding) is not None
    altered = Finding.from_dict({**finding.to_dict(), "resource": finding.resource.swapcase()})
    assert inventory.match(altered) is None
    other_port = atlassian_scan(fixtures, site=ATLASSIAN_SITE + ":8443").findings[0]
    assert inventory.match(other_port) is None
    assert card_stub_for(other_port)["discovery"]["accounts"] == [ATLASSIAN_SITE + ":8443"]


def test_atlassian_unknown_exports_keep_stable_separate_identities(fixtures, tmp_path):
    content = (fixtures / "saas" / "atlassian_shared_app.json").read_text()
    connectors = []
    for name in ("one", "two"):
        source = tmp_path / f"{name}.json"
        source.write_text(content, encoding="utf-8")
        connectors.append(ConnectorSpec("saas.atlassian", {"input": str(source)}))
    config = ScanConfig(connectors=connectors)
    first, second = Engine(config).run(), Engine(config).run()
    assert not first.complete and not second.complete
    assert len(first.findings) == len({finding.id for finding in first.findings}) == 2
    assert [finding.id for finding in first.findings] == [finding.id for finding in second.findings]


@pytest.mark.parametrize(
    "site",
    [
        "http://approved.atlassian.net",
        "https://user@approved.atlassian.net",
        "https://approved.atlassian.net/wiki",
        "https://approved.atlassian.net?site=other",
        "https://approved.atlassian.net#site",
        " https://approved.atlassian.net",
        "https://approved.atlassian.net\n",
        "https://approved.atlassian.net:bad",
        "https://approved.atlassian.net:0",
        "https://approved.atlassian.net:",
        "https://",
        123,
        [ATLASSIAN_SITE],
    ],
)
def test_atlassian_invalid_site_configuration_is_rejected(run_connector, site):
    with pytest.raises(ConnectorError, match="concrete HTTPS site origin"):
        run_connector("saas.atlassian", site=site)


@pytest.mark.parametrize(
    "account", [None, "", "unknown", "http://approved.atlassian.net", ATLASSIAN_SITE + "/wiki"]
)
def test_atlassian_invalid_finding_scope_cannot_bind_or_approve(account):
    finding = Finding(
        surface=Surface.SAAS,
        connector="saas.atlassian",
        kind=Kind.BOT_APP,
        title="Atlassian app: Claude",
        resource="atlassian:jira:app:com.example.Claude",
        resource_type="atlassian-app",
        provider="atlassian",
        account=account,
    )
    assert card_stub_for(finding)["discovery"]["resources"] == []
    inventory = Inventory(
        [InventoryEntry(agent_id="broad", resources=["*"], accounts=[account or ATLASSIAN_SITE])]
    )
    assert inventory.match(finding) is None
    assert finding.metadata["registry_match_reason"] == "missing-atlassian-account-scope"


def test_atlassian_untrusted_record_scope_cannot_supply_or_override_site(tmp_path):
    record = {
        "key": "com.example.Claude",
        "name": "Claude",
        "site": OTHER_ATLASSIAN_SITE,
        "_site": OTHER_ATLASSIAN_SITE,
        "account": OTHER_ATLASSIAN_SITE,
    }
    unscoped = scan(tmp_path, "saas.atlassian", [record])
    assert not unscoped.complete and unscoped.findings[0].account is None
    scoped = scan(tmp_path, "saas.atlassian", [record], site=ATLASSIAN_SITE)
    assert scoped.complete and scoped.findings[0].account == ATLASSIAN_SITE


def _atlassian_directory_scan(directory):
    return Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.atlassian", {"input": str(directory)})], parallel=1)
    ).run()


@pytest.mark.parametrize("forged_scope", [None, "forged-shared-scope"])
def test_atlassian_unscoped_directory_keeps_each_site_export_distinct(fixtures, tmp_path, forged_scope):
    export = json.loads((fixtures / "saas" / "atlassian_shared_app.json").read_text(encoding="utf-8"))
    if forged_scope is not None:
        for plugin in export["plugins"]:
            plugin["_unresolved_scope"] = forged_scope
    directory = tmp_path / "exports"
    directory.mkdir()
    for name in ("site-a.json", "site-b.json"):
        (directory / name).write_text(json.dumps(export), encoding="utf-8")

    report = _atlassian_directory_scan(directory)
    repeat = _atlassian_directory_scan(tmp_path / "exports" / ".." / "exports")

    assert not report.complete
    assert len(report.findings) == 2
    assert len({finding.id for finding in report.findings}) == 2
    assert len(merge(report.findings)) == 2
    assert all(finding.account is None for finding in report.findings)
    assert forged_scope is None or all(
        forged_scope not in str(finding.identity_discriminator) for finding in report.findings
    )
    # Equivalent spellings of the same input keep the same finding IDs.
    assert {finding.id for finding in repeat.findings} == {finding.id for finding in report.findings}


def test_atlassian_configured_site_ignores_per_file_scope(fixtures, tmp_path):
    export = (fixtures / "saas" / "atlassian_shared_app.json").read_text(encoding="utf-8")
    directory = tmp_path / "exports"
    directory.mkdir()
    for name in ("one.json", "two.json"):
        (directory / name).write_text(export, encoding="utf-8")
    config = {"input": str(directory), "site": ATLASSIAN_SITE}

    report = Engine(ScanConfig(connectors=[ConnectorSpec("saas.atlassian", config)], parallel=1)).run()

    assert report.complete
    assert len({finding.id for finding in report.findings}) == 1
    assert all(finding.identity_discriminator == "atlassian-app" for finding in report.findings)


def test_slack_same_app_in_same_named_workspaces_stays_separate(tmp_path):
    first = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T1", "name": "Engineering"}, SLACK_APP])
    second = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T2", "name": "Engineering"}, SLACK_APP])
    assert first.complete and second.complete
    combined = merge(first.findings + second.findings)
    assert len(combined) == 2
    assert {finding.account for finding in combined} == {"T1", "T2"}
    assert {finding.metadata["workspace_name"] for finding in combined} == {"Engineering"}


def test_slack_workspace_rename_preserves_finding_identity(tmp_path):
    first = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T1", "name": "Before"}, SLACK_APP])
    second = scan(tmp_path, "saas.slack", [SLACK_APP, {"_kind": "team", "id": "T1", "name": "After"}])
    assert first.complete and second.complete
    assert first.findings[0].id == second.findings[0].id
    assert second.findings[0].metadata["workspace_name"] == "After"


@pytest.mark.parametrize(
    "records,settings",
    [
        ([SLACK_APP], {}),
        ([], {}),
        ([{"_kind": "team", "id": "T1"}, SLACK_APP], {"team_id": "T2"}),
        ([{"_kind": "team", "id": "T1"}, SLACK_APP, {"_kind": "team", "id": "T2"}], {}),
        ([{"_kind": "team", "id": "T1"}, SLACK_APP, {"_kind": "team", "name": "Missing"}], {}),
        ([SLACK_APP, {"_kind": "team", "id": None}], {"team_id": "T1"}),
        ([SLACK_APP, {"_kind": "team", "id": "Engineering"}], {}),
        ([{"_kind": "team", "id": "T1"}, {**SLACK_APP, "team_id": "T2"}], {}),
        ([{"_kind": "team", "id": "T1"}, {**SLACK_APP, "team_id": []}], {}),
    ],
)
def test_slack_missing_or_conflicting_scope_cannot_pass_or_relabel(tmp_path, records, settings):
    result = scan(tmp_path, "saas.slack", records, **settings)
    assert not result.complete and not result.findings
    assert result.stats[0].warnings


def test_slack_legacy_export_uses_explicit_scope_without_claiming_live_verification(tmp_path):
    result = scan(tmp_path, "saas.slack", [SLACK_APP], team_id="T1")
    assert result.complete and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.account == "T1"
    assert finding.metadata["workspace_scope_source"] == "operator-configured"
    assert finding.metadata["workspace_name"] is None


def test_slack_repeated_matching_team_records_are_safe(tmp_path):
    team = {"_kind": "team", "id": "T1", "name": "Engineering"}
    result = scan(tmp_path, "saas.slack", [team, SLACK_APP, team], team_id="T1")
    assert result.complete and len(result.findings) == 1
    assert result.findings[0].metadata["workspace_scope_source"] == "team-record"


@pytest.mark.parametrize("team_id", ["Engineering", "", " T1", 123, ["T1"]])
def test_slack_config_scope_requires_workspace_id(index, team_id):
    with pytest.raises(ConnectorError, match="Slack workspace ID"):
        SlackConnector(ConnectorContext(index=index, config={"team_id": team_id}))


@pytest.mark.parametrize(
    "record",
    [
        {"_kind": "teamsApp", "displayName": "ChatGPT", "distributionMethod": "organization"},
        {**TEAMS_APP, "id": None},
        {**TEAMS_APP, "id": " "},
        {**TEAMS_APP, "id": ["bad"]},
        {**TEAMS_APP, "_kind": "unsupported"},
        {**TEAMS_APP, "displayName": []},
        {**TEAMS_APP, "appDefinitions": None},
        {**TEAMS_APP, "appDefinitions": {}},
        {**TEAMS_APP, "appDefinitions": [123]},
        {**TEAMS_APP, "appDefinitions": [{"bot": []}]},
        {**TEAMS_APP, "appDefinitions": [{"bot": {}}]},
        {**TEAMS_APP, "appDefinitions": [{"teamsAppId": "other-app"}]},
        {**TEAMS_APP, "appDefinitions": [{"createdBy": {"user": {"displayName": []}}}]},
        {**TEAMS_APP, "appDefinitions": [{"authorization": []}]},
        {
            **TEAMS_APP,
            "appDefinitions": [
                {"authorization": {"requiredPermissionSet": {"resourceSpecificPermissions": None}}}
            ],
        },
        {
            **TEAMS_APP,
            "appDefinitions": [
                {
                    "authorization": {
                        "requiredPermissionSet": {"resourceSpecificPermissions": [{"permissionValue": []}]}
                    }
                }
            ],
        },
        {"_kind": "installedApp", "id": "installation-is-not-app-identity"},
        {"_kind": "installedApp", "teamsApp": []},
        {"_kind": "installedApp", "teamsApp": {"id": "A1"}, "teamsAppDefinition": []},
        {"_kind": "installedApp", "teamsApp": {"id": "A1"}, "teamsAppDefinition": {"teamsAppId": "A2"}},
    ],
)
def test_teams_malformed_records_are_incomplete_and_keep_valid_neighbors(tmp_path, record):
    result = scan(tmp_path, "saas.microsoft-teams", [record, TEAMS_APP], tenant_id="tenant-a")
    assert not result.complete
    assert [finding.resource for finding in result.findings] == ["teams:app:valid-app"]
    assert result.stats[0].warnings and not result.stats[0].errors


def test_teams_missing_app_id_never_invents_none_resource(tmp_path):
    result = scan(
        tmp_path,
        "saas.microsoft-teams",
        [{"_kind": "teamsApp", "distributionMethod": "organization", "displayName": "ChatGPT"}],
    )
    assert not result.complete and not result.findings


def test_teams_installation_uses_definition_catalog_identity(tmp_path):
    result = scan(
        tmp_path,
        "saas.microsoft-teams",
        [
            {
                "_kind": "installedApp",
                "id": "installation-1",
                "_team": "Engineering",
                "teamsAppDefinition": {
                    "teamsAppId": "catalog-1",
                    "displayName": "ChatGPT",
                    "bot": {"id": "bot-1"},
                },
            }
        ],
        tenant_id="tenant-a",
    )
    assert result.complete
    (finding,) = result.findings
    assert finding.resource == "teams:app:catalog-1"
    assert finding.metadata["install_count"] == 1


def test_teams_malformed_live_team_does_not_abort_other_inventory(index):
    connector = TeamsConnector(ConnectorContext(index=index, config={"tenant_id": "tenant-a"}))
    http = Mock()
    connector._client = Mock(return_value=http)

    def pages(path, **kwargs):
        if path == "/appCatalogs/teamsApps":
            yield TEAMS_APP
        elif path == "/teams":
            yield {"displayName": "Missing identity"}
            yield {"id": "team-1"}
        elif path == "/teams/team-1/installedApps":
            yield {"teamsApp": {"id": "valid-app"}}
        else:
            raise AssertionError("unexpected inventory path")

    http.paginate_odata.side_effect = pages
    findings = connector.run()
    assert len(findings) == 1 and findings[0].metadata["install_count"] == 1
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def _teams_review_records(fixtures):
    return json.loads((fixtures / "saas" / "teams_review_versions.json").read_text(encoding="utf-8"))


def test_teams_catalog_version_cannot_hide_installed_bot_or_requested_permissions(tmp_path, fixtures):
    records = _teams_review_records(fixtures)[:2]
    result = scan(tmp_path, "saas.microsoft-teams", records, tenant_id="tenant-a")
    assert result.complete
    (finding,) = result.findings
    assert finding.metadata["bot_id"] == "review-bot-one"
    assert finding.metadata["version"] is None
    assert finding.metadata["versions"] == ["1.0.0", "2.0.0"]
    assert finding.metadata["rsc_permissions"] == ["ChannelMessage.Read.Group"]
    assert finding.metadata["rsc_permission_basis"] == "definition-requested"
    observations = finding.metadata["definition_observations"]
    installed = next(item for item in observations if item["source"] == "installation")
    assert installed["definition_id"] == "definition-v1"
    assert installed["version"] == "1.0.0"
    assert installed["installation_count"] == installed["team_count"] == 1
    assert installed["teams"] == [{"team_id": "team-engineering", "team_name": "Engineering"}]
    assert installed["requested_rsc_permissions"] == [
        {"permission": "ChannelMessage.Read.Group", "type": "Application"}
    ]
    assert any("grants are not verified" in evidence.description for evidence in finding.evidence)


def test_teams_retains_multiple_installed_versions_without_inventing_one_bot_identity(tmp_path, fixtures):
    result = scan(tmp_path, "saas.microsoft-teams", _teams_review_records(fixtures), tenant_id="tenant-a")
    assert result.complete
    (finding,) = result.findings
    assert finding.metadata["bot_id"] is None
    assert finding.metadata["bot_ids"] == ["review-bot-one", "review-bot-two"]
    assert finding.metadata["versions"] == ["1.0.0", "2.0.0", "3.0.0"]
    assert finding.metadata["rsc_permissions"] == ["ChannelMessage.Read.Group", "TeamSettings.Read.Group"]
    assert finding.metadata["install_count"] == 2
    installed = [d for d in finding.metadata["definition_observations"] if d["source"] == "installation"]
    assert {(d["version"], tuple(t["team_id"] for t in d["teams"]), d["bot_id"]) for d in installed} == {
        ("1.0.0", ("team-engineering",), "review-bot-one"),
        ("3.0.0", ("team-security",), "review-bot-two"),
    }


def test_teams_catalog_definition_and_record_order_do_not_change_assessment(tmp_path, fixtures):
    records = _teams_review_records(fixtures)
    records[0]["appDefinitions"].append(copy.deepcopy(records[1]["teamsAppDefinition"]))
    first = scan(tmp_path, "saas.microsoft-teams", records, tenant_id="tenant-a")
    records[0]["appDefinitions"].reverse()
    second = scan(tmp_path, "saas.microsoft-teams", records[::-1], tenant_id="tenant-a")
    assert first.complete and second.complete
    one, two = first.findings[0], second.findings[0]
    assert one.id == two.id
    assert one.metadata == two.metadata
    assert one.capabilities == two.capabilities and one.confidence == two.confidence


def test_teams_definition_text_is_matched_separately_without_synthesizing_product_names(
    tmp_path, index, monkeypatch
):
    inputs = []
    real_match = index.match_name

    def match_name(text):
        inputs.append(text)
        return real_match(text)

    monkeypatch.setattr(index, "match_name", match_name)
    result = scan(
        tmp_path,
        "saas.microsoft-teams",
        [
            {
                **TEAMS_APP,
                "appDefinitions": [
                    {"id": "first", "description": "Claude"},
                    {"id": "second", "description": "Code"},
                ],
            }
        ],
        index=index,
        tenant_id="tenant-a",
    )
    assert result.complete
    assert "Claude" in inputs and "Code" in inputs and "Claude Code" not in inputs


def test_teams_installations_of_one_definition_are_counted_with_a_bounded_team_sample(tmp_path):
    # One observation per installation grew a finding by about 300 bytes per team: past
    # the sanitization limit it was omitted and the scan was incomplete.
    definition = {
        "id": "definition-1",
        "teamsAppId": "org-bot",
        "version": "1.0.0",
        "bot": {"id": "bot-1"},
        "authorization": {
            "requiredPermissionSet": {
                "resourceSpecificPermissions": [
                    {"permissionValue": "ChannelMessage.Read.Group", "permissionType": "Application"}
                ]
            }
        },
    }
    catalog = {
        **TEAMS_APP,
        "id": "org-bot",
        "displayName": "Ops Copilot",
        "appDefinitions": [{**definition, "publishingState": "published"}],
    }
    installations = [
        {
            "_kind": "installedApp",
            "id": f"installation-{number}",
            "_team": f"Team {number:04d}",
            "_team_id": f"team-{number:04d}",
            "teamsApp": {"id": "org-bot", "distributionMethod": "organization"},
            "teamsAppDefinition": definition,
        }
        for number in range(8000)
    ]
    result = scan(tmp_path, "saas.microsoft-teams", [catalog, *installations], tenant_id="tenant-a")
    assert result.complete and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["install_count"] == 8000 and not finding.metadata["definition_conflicts"]
    (installed,) = [d for d in finding.metadata["definition_observations"] if d["source"] == "installation"]
    assert installed["installation_count"] == installed["team_count"] == 8000
    assert installed["teams"] == [
        {"team_id": f"team-{number:04d}", "team_name": f"Team {number:04d}"} for number in range(20)
    ]
    assert len(finding.metadata["installed_teams"]) == 20
    assert len(json.dumps(finding.to_dict())) < 10_000


def _distinct_teams_definitions(count, *extra):
    """A catalog definition and ``count`` installations, each of a definition of its own."""
    catalog = {
        **TEAMS_APP,
        "id": "org-bot",
        "displayName": "Ops Copilot",
        "appDefinitions": [
            {
                "id": "definition-0000",
                "teamsAppId": "org-bot",
                "version": "1.0.0",
                "publishingState": "published",
                "bot": {"id": "bot-1"},
            }
        ],
    }
    definitions = [
        {
            "id": f"definition-{number:04d}",
            "teamsAppId": "org-bot",
            "version": f"1.{number}.0",
            "bot": {"id": "bot-1"},
        }
        for number in range(1, count + 1)
    ]
    # The last definition sorts after every listed observation; its permission must still count.
    definitions[-1]["authorization"] = {
        "requiredPermissionSet": {
            "resourceSpecificPermissions": [
                {"permissionValue": "ChannelMessage.Read.Group", "permissionType": "Application"}
            ]
        }
    }
    installations = [
        {
            "_kind": "installedApp",
            "id": f"installation-{number}",
            "_team": f"Team {number:04d}",
            "_team_id": f"team-{number:04d}",
            "teamsApp": {"id": "org-bot", "distributionMethod": "organization"},
            "teamsAppDefinition": definition,
        }
        for number, definition in enumerate([*definitions, *extra], 1)
    ]
    return [catalog, *installations]


def test_teams_distinct_definitions_are_listed_as_a_bounded_sample_with_an_omitted_count(tmp_path):
    # One observation per distinct definition grew a finding by about 300 bytes each:
    # 3,000 gave 953 KB, and at 8,000 the finding passed the sanitization limit, was
    # omitted and left the scan incomplete.
    result = scan(tmp_path, "saas.microsoft-teams", _distinct_teams_definitions(3000), tenant_id="tenant-a")
    assert result.complete, result.stats[0].warnings
    (finding,) = result.findings
    metadata = finding.metadata
    assert metadata["install_count"] == 3000 and not metadata["definition_conflicts"]
    observations = metadata["definition_observations"]
    assert [d["definition_id"] for d in observations] == [f"definition-{number:04d}" for number in range(20)]
    assert metadata["definition_observations_omitted"] == 3001 - 20
    assert metadata["versions"] == sorted(["1.0.0", *(f"1.{number}.0" for number in range(1, 3001))])[:20]
    assert metadata["versions_omitted"] == 3001 - 20
    assert metadata["version"] is None
    assert (
        metadata["bot_ids"] == ["bot-1"]
        and metadata["bot_ids_omitted"] == 0
        and metadata["bot_id"] == "bot-1"
    )
    # Derived from every observation, not only the listed ones.
    assert metadata["rsc_permissions"] == ["ChannelMessage.Read.Group"]
    (app_evidence,) = [evidence for evidence in finding.evidence if evidence.signal == "teams:app"]
    assert "1.10.0, 1.100.0," in app_evidence.description and "and 2981 more" in app_evidence.description
    assert len(json.dumps(finding.to_dict())) < 15_000


def test_teams_conflict_among_omitted_definition_observations_is_still_detected(tmp_path):
    conflicting = {
        "id": "definition-2999",
        "teamsAppId": "org-bot",
        "version": "9.9.9",
        "bot": {"id": "bot-1"},
    }
    result = scan(
        tmp_path, "saas.microsoft-teams", _distinct_teams_definitions(3000, conflicting), tenant_id="tenant-a"
    )
    assert not result.complete
    assert any("conflicting Teams definition observations" in w for w in result.stats[0].warnings)
    (finding,) = result.findings
    assert finding.metadata["definition_conflicts"]
    assert all(d["definition_id"] != "definition-2999" for d in finding.metadata["definition_observations"])
    assert finding.metadata["definition_observations_omitted"] == 3002 - 20


def test_teams_repeated_catalog_snapshot_with_reordered_definitions_is_not_a_conflict(tmp_path, fixtures):
    records = _teams_review_records(fixtures)
    catalog = records[0]
    catalog["appDefinitions"].append(copy.deepcopy(records[1]["teamsAppDefinition"]))
    reordered = copy.deepcopy(catalog)
    reordered["appDefinitions"].reverse()
    result = scan(tmp_path, "saas.microsoft-teams", [catalog, reordered], tenant_id="tenant-a")
    assert result.complete and len(result.findings) == 1
    assert not result.findings[0].metadata["definition_conflicts"]
    assert result.findings[0].metadata["rsc_permissions"] == ["ChannelMessage.Read.Group"]


def test_teams_catalog_cannot_claim_internal_installation_marker_to_hide_definitions(tmp_path, fixtures):
    catalog, installation, _ = _teams_review_records(fixtures)
    catalog["_from_install"] = True
    catalog["appDefinitions"] = [installation["teamsAppDefinition"]]
    result = scan(tmp_path, "saas.microsoft-teams", [catalog], tenant_id="tenant-a")
    assert result.complete
    assert result.findings[0].metadata["bot_id"] == "review-bot-one"
    assert result.findings[0].metadata["definition_observations"][0]["source"] == "catalog"


def test_teams_installation_only_versions_do_not_choose_first_definition_name(tmp_path, fixtures):
    _, first, second = _teams_review_records(fixtures)
    first["teamsAppDefinition"]["displayName"] = "Previous app name"
    second["teamsAppDefinition"]["displayName"] = "Changed app name"
    one = scan(tmp_path, "saas.microsoft-teams", [first, second], tenant_id="tenant-a")
    two = scan(tmp_path, "saas.microsoft-teams", [second, first], tenant_id="tenant-a")
    assert one.complete and two.complete
    assert one.findings[0].title == two.findings[0].title == "Teams app with bot: review-app"
    assert one.findings[0].metadata == two.findings[0].metadata


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("identity", ["id", "version"])
def test_teams_conflicting_definition_facts_are_incomplete_and_both_observations_survive(
    tmp_path, fixtures, reverse, identity
):
    records = _teams_review_records(fixtures)[:2]
    original = copy.deepcopy(records[1]["teamsAppDefinition"])
    if identity == "version":
        original.pop("id")
        records[1]["teamsAppDefinition"].pop("id")
    records[0]["appDefinitions"] = [original]
    records[1]["teamsAppDefinition"]["bot"] = {"id": "conflicting-bot"}
    records[1]["teamsAppDefinition"]["authorization"]["requiredPermissionSet"][
        "resourceSpecificPermissions"
    ] = []
    result = scan(
        tmp_path, "saas.microsoft-teams", records[::-1] if reverse else records, tenant_id="tenant-a"
    )
    assert not result.complete and len(result.findings) == 1
    assert any("conflicting Teams definition observations" in warning for warning in result.stats[0].warnings)
    metadata = result.findings[0].metadata
    assert metadata["definition_conflicts"] is True
    assert metadata["bot_id"] is None
    assert metadata["bot_ids"] == ["conflicting-bot", "review-bot-one"]
    assert metadata["rsc_permissions"] == ["ChannelMessage.Read.Group"]
    assert {d["source"] for d in metadata["definition_observations"]} == {"catalog", "installation"}


def test_teams_partial_definition_does_not_erase_observed_facts_or_invent_empty_permissions(
    tmp_path, fixtures
):
    records = _teams_review_records(fixtures)[:2]
    records[0]["appDefinitions"] = [copy.deepcopy(records[1]["teamsAppDefinition"])]
    records[1]["teamsAppDefinition"].pop("bot")
    records[1]["teamsAppDefinition"].pop("authorization")
    result = scan(tmp_path, "saas.microsoft-teams", records, tenant_id="tenant-a")
    assert result.complete
    metadata = result.findings[0].metadata
    assert metadata["bot_id"] == "review-bot-one" and metadata["version"] == "1.0.0"
    assert metadata["rsc_permissions"] == ["ChannelMessage.Read.Group"]
    assert not metadata["definition_conflicts"]
    installed = next(d for d in metadata["definition_observations"] if d["source"] == "installation")
    assert installed["bot_observed"] is False
    assert installed["requested_rsc_permissions"] is None


@pytest.mark.parametrize(
    "malformed", [{"bot": []}, {"version": []}, {"authorization": {"requiredPermissionSet": []}}]
)
def test_teams_malformed_installation_definition_keeps_valid_installed_versions(
    tmp_path, fixtures, malformed
):
    records = _teams_review_records(fixtures)
    records[1]["teamsAppDefinition"].update(malformed)
    result = scan(tmp_path, "saas.microsoft-teams", records, tenant_id="tenant-a")
    assert not result.complete and len(result.findings) == 1
    assert result.findings[0].metadata["bot_id"] == "review-bot-two"
    assert result.findings[0].metadata["rsc_permissions"] == ["TeamSettings.Read.Group"]
    assert not result.stats[0].errors


def test_teams_live_installed_definition_keeps_team_id_and_version_provenance(index, fixtures, monkeypatch):
    catalog, installation, _ = _teams_review_records(fixtures)
    http = Mock()

    def pages(path, **kwargs):
        if path == "/appCatalogs/teamsApps":
            yield catalog
        elif path == "/teams":
            yield {"id": "live-team-id", "displayName": "Live team"}
        else:
            assert path == "/teams/live-team-id/installedApps"
            yield installation

    http.paginate_odata.side_effect = pages
    monkeypatch.setattr(TeamsConnector, "_client", lambda self: http)
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.microsoft-teams", {"tenant_id": "tenant-a"})]), index=index
    ).run()
    assert result.complete
    observation = next(
        d for d in result.findings[0].metadata["definition_observations"] if d["source"] == "installation"
    )
    assert observation["teams"] == [{"team_id": "live-team-id", "team_name": "Live team"}]
    assert observation["version"] == "1.0.0"
