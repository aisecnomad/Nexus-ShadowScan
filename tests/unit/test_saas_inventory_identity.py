"""Tenant identity and malformed provider data must survive complete scan gates."""

from __future__ import annotations

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


def scan(tmp_path, connector, records, **settings):
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    return Engine(
        ScanConfig(connectors=[ConnectorSpec(connector, {"input": str(source), **settings})], parallel=1)
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
