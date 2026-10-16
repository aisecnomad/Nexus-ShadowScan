"""Microsoft Teams: org-catalog and store apps with bots / Copilot agents installed in teams.

Live (Microsoft Graph, app permissions ``AppCatalog.Read.All``, ``Team.ReadBasic.All``,
``TeamsAppInstallation.ReadForTeam.All``):

* ``/appCatalogs/teamsApps?$expand=appDefinitions($expand=bot)`` – custom (organization) apps
* ``/teams`` + ``/teams/{id}/installedApps?$expand=teamsApp,teamsAppDefinition`` – installations (capped)

Offline export: teamsApp objects (with ``appDefinitions``) and/or installedApps objects.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar
from urllib.parse import quote

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.common import apply_matches, config_boolean, failure_summary, finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path

GRAPH = "https://graph.microsoft.com/v1.0"
# Team names (and IDs) a finding lists, in total and per observed definition.
_TEAM_SAMPLE = 20
# Definition observations, versions and bot IDs a finding lists; the rest are
# counted, so an app with thousands of distinct definitions keeps a bounded finding.
_DEFINITION_SAMPLE = 20


class TeamsConnector(BaseConnector):
    name: ClassVar[str] = "saas.microsoft-teams"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "microsoft-teams"
    description: ClassVar[str] = (
        "Teams apps (custom + store) with bots, message extensions and Copilot agents, plus their "
        "installations."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "tenant_id": "env AZURE_TENANT_ID",
        "client_id": "env AZURE_CLIENT_ID",
        "client_secret": "env AZURE_CLIENT_SECRET",
        "access_token": "pre-issued Graph token (env GRAPH_ACCESS_TOKEN)",
        "include_store": (
            "also list store apps in the catalog (default false; installations always inspected)"
        ),
        "max_teams": "cap on teams whose installed apps are enumerated, a positive integer (default 300)",
        "input": "offline: JSON export of teamsApps / installedApps",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.tenant = ctx.get("tenant_id", env="AZURE_TENANT_ID")
        self.include_store = config_boolean(ctx.get("include_store", False), "include_store")
        self.max_teams = _positive_limit(ctx.get("max_teams", 300), "max_teams")

    def _client(self) -> HttpClient:
        token = self.ctx.get("access_token", env="GRAPH_ACCESS_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="AZURE_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="AZURE_CLIENT_SECRET")
            if not (self.tenant and cid and secret):
                raise ConnectorError(
                    "saas.microsoft-teams: tenant_id, client_id, client_secret (or access_token) required"
                )
            client = HttpClient()
            resp = client.post(
                f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": cid,
                    "client_secret": secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            token = client.read_json_response(resp)["access_token"]
        return HttpClient(GRAPH, headers={"Authorization": f"Bearer {token}"})

    def _pages(self, http: HttpClient, path: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        try:
            yield from http.paginate_odata(path, **kwargs)
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            status = failure_summary(exc)
            self.ctx.warn(f"saas.microsoft-teams: collection incomplete for {path} ({status})")

    def collect(self) -> Iterable[dict[str, Any]]:
        http = self._client()
        flt = None if self.include_store else "distributionMethod eq 'organization'"
        params = {"$expand": "appDefinitions($expand=bot)"}
        if flt:
            params["$filter"] = flt
        for app in self._pages(http, "/appCatalogs/teamsApps", params=params):
            app["_kind"] = "teamsApp"
            yield app
        for n, team in enumerate(
            self._pages(http, "/teams", params={"$select": "id,displayName", "$top": 999})
        ):
            if n >= self.max_teams:
                self.ctx.warn("saas.microsoft-teams: max_teams reached")
                break
            if not self._record_fields_valid(team, required=("id",), strings=("displayName",)):
                self.ctx.warn("saas.microsoft-teams: malformed team identity; installed-app coverage unknown")
                continue
            team_path = quote(str(team["id"]), safe="")
            for inst in self._pages(
                http, f"/teams/{team_path}/installedApps", params={"$expand": "teamsApp,teamsAppDefinition"}
            ):
                inst["_kind"] = "installedApp"
                inst["_team"] = team.get("displayName")
                inst["_team_id"] = team["id"]
                yield inst

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        apps: dict[str, dict[str, Any]] = {}
        conflicting_apps: set[str] = set()
        installs: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                self.ctx.warn(
                    "saas.microsoft-teams: unsupported or malformed app record; coverage incomplete"
                )
                continue
            if kind == "teamsApp":
                # This marker is local bookkeeping, never provider/export authority.
                rec = {key: value for key, value in rec.items() if key != "_from_install"}
                app_id = rec["id"]
                existing = apps.get(app_id)
                if existing is None or existing.get("_from_install"):
                    apps[app_id] = rec
                elif not self._same_app_snapshot(existing, rec) and app_id not in conflicting_apps:
                    conflicting_apps.add(app_id)
                    self.ctx.warn(
                        "saas.microsoft-teams: conflicting Teams app records; "
                        "app identity coverage incomplete"
                    )
            else:
                app = rec.get("teamsApp") or {}
                definition = rec.get("teamsAppDefinition") or {}
                app_id = app.get("id") or definition["teamsAppId"]
                installs.setdefault(app_id, []).append(rec)
                if app_id not in apps:
                    apps[app_id] = {
                        "id": app_id,
                        **app,
                        "_from_install": True,
                    }
        for app_id, app in apps.items():
            if app_id in conflicting_apps:
                continue
            self.ctx.examined()
            try:
                f = self._app_finding(app_id, app, installs.get(app_id, []))
            except (
                AttributeError,
                TypeError,
                ValueError,
                KeyError,
                RecursionError,
                MatchTimeoutError,
            ) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(
                    f"saas.microsoft-teams: skipped a malformed app record ({type(exc).__name__}){detail}"
                )
                continue
            if f:
                yield f

    def _record_kind(self, rec: dict[str, Any]) -> str | None:
        if not self._record_fields_valid(
            rec, strings=("_kind", "id", "_team", "_team_id"), mappings=("teamsApp", "teamsAppDefinition")
        ):
            return None
        kind = rec.get("_kind") or (
            "installedApp" if "teamsApp" in rec or "teamsAppDefinition" in rec else "teamsApp"
        )
        if kind == "teamsApp":
            return kind if self._valid_app(rec) else None
        if kind != "installedApp":
            return None
        app = rec.get("teamsApp")
        definition = rec.get("teamsAppDefinition")
        if app is not None and not self._valid_app(app):
            return None
        if definition is not None and not self._valid_definition(definition):
            return None
        app_id = (app or {}).get("id")
        definition_app_id = (definition or {}).get("teamsAppId")
        # An installation ID is a different resource. It cannot substitute for
        # the catalog app ID when the requested expansion is absent or invalid.
        if not (app_id or definition_app_id) or (
            app_id and definition_app_id and app_id != definition_app_id
        ):
            return None
        return kind

    @staticmethod
    def _same_app_snapshot(left: dict[str, Any], right: dict[str, Any]) -> bool:
        # Graph does not promise a version order for expanded definitions.
        def normalized(app: dict[str, Any]) -> dict[str, Any]:
            return {
                **app,
                "appDefinitions": sorted(
                    json.dumps(definition, sort_keys=True) for definition in app.get("appDefinitions", [])
                ),
            }

        return normalized(left) == normalized(right)

    def _valid_app(self, app: Any) -> bool:
        if not self._record_fields_valid(
            app, required=("id",), strings=("displayName", "distributionMethod", "externalId")
        ):
            return False
        if "appDefinitions" not in app:
            return True
        definitions = app["appDefinitions"]
        return isinstance(definitions, list) and all(
            self._valid_definition(definition) and definition.get("teamsAppId", app["id"]) == app["id"]
            for definition in definitions
        )

    def _valid_definition(self, definition: Any) -> bool:
        if not self._record_fields_valid(
            definition,
            strings=(
                "id",
                "teamsAppId",
                "version",
                "displayName",
                "publishingState",
                "description",
                "shortDescription",
                "lastModifiedDateTime",
            ),
            mappings=("bot", "createdBy", "authorization"),
        ):
            return False
        if "teamsAppId" in definition and not self._record_fields_valid(definition, required=("teamsAppId",)):
            return False
        if definition.get("bot") is not None and not self._record_fields_valid(
            definition["bot"], required=("id",)
        ):
            return False
        creator = definition.get("createdBy") or {}
        if not self._record_fields_valid(creator, mappings=("user", "application")):
            return False
        if any(
            not self._record_fields_valid(creator[key], strings=("id", "displayName"))
            for key in ("user", "application")
            if creator.get(key) is not None
        ):
            return False
        authorization = definition.get("authorization") or {}
        if not self._record_fields_valid(authorization, mappings=("requiredPermissionSet",)):
            return False
        required = authorization.get("requiredPermissionSet") or {}
        if not self._record_fields_valid(required):
            return False
        if "resourceSpecificPermissions" not in required:
            return True
        permissions = required["resourceSpecificPermissions"]
        return isinstance(permissions, list) and all(
            self._record_fields_valid(permission, required=("permissionValue",), strings=("permissionType",))
            for permission in permissions
        )

    def _definitions(
        self, app: dict[str, Any], installs: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
        """Every observed definition, with its source; no catalog version is assumed installed.

        Expansions can omit fields, so only contradictory *present* facts for
        the same definition ID or version poison coverage. Preserve both
        observations rather than choosing an apparently safer snapshot.
        """
        definitions: list[dict[str, Any]] = []
        observations: dict[str, dict[str, Any]] = {}
        # Per observation: its installations' known (team ID, team name) pairs and their count.
        installed: dict[str, tuple[set[tuple[str, str]], list[int]]] = {}
        known: dict[tuple[str, str], dict[str, Any]] = {}
        conflicting = False

        def add(definition: dict[str, Any], source: str, installation: dict[str, Any] | None = None) -> None:
            nonlocal conflicting
            definitions.append(definition)
            permissions = get_path(definition, "authorization.requiredPermissionSet") or {}
            rsc = permissions.get("resourceSpecificPermissions")
            requested = (
                sorted({(p["permissionValue"], p.get("permissionType") or "") for p in rsc})
                if rsc is not None
                else None
            )
            facts: dict[str, Any] = {
                key: definition[key] for key in ("id", "version", "publishingState") if key in definition
            }
            if "bot" in definition:
                facts["bot_id"] = get_path(definition, "bot.id")
            if requested is not None:
                facts["requested_rsc_permissions"] = requested
            for field in ("id", "version"):
                if not definition.get(field):
                    continue
                previous = known.setdefault((field, definition[field]), {})
                if any(previous[key] != value for key, value in facts.items() if key in previous):
                    conflicting = True
                previous.update(facts)
            record = {
                "source": source,
                "definition_id": definition.get("id"),
                "version": definition.get("version"),
                "publishing_state": definition.get("publishingState"),
                "bot_id": get_path(definition, "bot.id"),
                "bot_observed": "bot" in definition,
                # None is an omitted expansion, distinct from an observed empty set.
                "requested_rsc_permissions": (
                    [{"permission": permission, "type": kind or None} for permission, kind in requested]
                    if requested is not None
                    else None
                ),
            }
            # One observation per distinct definition and source: a tenant can install
            # an app in thousands of teams, so installations are counted and sampled.
            key = json.dumps(record, sort_keys=True)
            observations.setdefault(key, record)
            if installation is not None:
                teams, count = installed.setdefault(key, (set(), [0]))
                count[0] += 1
                team = (str(installation.get("_team_id") or ""), str(installation.get("_team") or ""))
                if any(team):
                    teams.add(team)

        if not app.get("_from_install"):
            for definition in app.get("appDefinitions") or []:
                add(definition, "catalog")
        for installation in installs:
            for definition in (installation.get("teamsApp") or {}).get("appDefinitions") or []:
                add(definition, "installation-catalog", installation)
            definition = installation.get("teamsAppDefinition")
            if definition is not None:
                add(definition, "installation", installation)
        if conflicting:
            self.ctx.warn(
                "saas.microsoft-teams: conflicting Teams definition observations; "
                "version and permission coverage incomplete"
            )

        def summary(key: str) -> dict[str, Any]:
            if key not in installed:
                return observations[key]
            teams, (count,) = installed[key]
            return {
                **observations[key],
                "installation_count": count,
                "team_count": len(teams),
                "teams": [
                    {"team_id": team_id or None, "team_name": team_name or None}
                    for team_id, team_name in sorted(teams)[:_TEAM_SAMPLE]
                ],
            }

        return definitions, [summary(key) for key in sorted(observations)], conflicting

    def _app_finding(
        self, app_id: str, app: dict[str, Any], installs: list[dict[str, Any]]
    ) -> Finding | None:
        defs, observations, conflicting = self._definitions(app, installs)

        def values(path: str) -> list[str]:
            return sorted({value for definition in defs if (value := get_path(definition, path))})

        def only(values: list[str]) -> str | None:
            return values[0] if len(values) == 1 else None

        names = values("displayName")
        team_names = sorted({str(i.get("_team")) for i in installs if i.get("_team")})
        name = app.get("displayName") or only(names) or app_id
        bot_ids = values("bot.id")
        versions = values("version")
        perms = sorted(
            {
                permission["permission"]
                for observation in observations
                for permission in observation["requested_rsc_permissions"] or []
            }
        )
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Teams app{' with bot' if bot_ids else ''}: {name}",
            resource=f"teams:app:{app_id}",
            resource_type="teams-app",
            provider="microsoft-teams",
            account=self.tenant,
            owner=only(
                sorted(
                    set(values("createdBy.user.displayName") + values("createdBy.application.displayName"))
                )
            ),
            first_seen=only(values("lastModifiedDateTime")),
        )
        assess_app(
            self.index,
            f,
            name=name,
            scopes=perms,
            aliases=names
            + values("description")
            + values("shortDescription")
            + values("createdBy.user.displayName")
            + values("createdBy.application.displayName"),
        )
        for bot_id in bot_ids:
            apply_matches(f, self.index.match_client_id(bot_id))
        is_custom = app.get("distributionMethod") == "organization"
        if not f.frameworks and not bot_ids and not is_custom:
            return None
        listed_versions = ", ".join(versions[:_DEFINITION_SAMPLE]) or "unknown"
        if len(versions) > _DEFINITION_SAMPLE:
            listed_versions += f" and {len(versions) - _DEFINITION_SAMPLE} more"
        f.add_evidence(
            Evidence(
                signal="teams:app",
                description=(
                    f"{app.get('distributionMethod') or 'unknown'} app '{name}' "
                    f"observed versions: {listed_versions}; "
                    f"{len(installs)} observed installation(s); "
                    f"definition-requested RSC permissions: {', '.join(perms) or 'none observed'}; "
                    "grants are not verified"
                ),
                weight=0.35 if bot_ids else 0.15,
            )
        )
        if bot_ids:
            f.add_tag("bot")
            f.add_framework("framework.bot-framework")
        if is_custom:
            f.add_tag("custom-app")
        f.metadata.update(
            {
                "distribution": app.get("distributionMethod"),
                "external_id": app.get("externalId"),
                "version": only(versions),
                "versions": versions[:_DEFINITION_SAMPLE],
                "versions_omitted": max(0, len(versions) - _DEFINITION_SAMPLE),
                "bot_id": only(bot_ids),
                "bot_ids": bot_ids[:_DEFINITION_SAMPLE],
                "bot_ids_omitted": max(0, len(bot_ids) - _DEFINITION_SAMPLE),
                "publishing_state": only(values("publishingState")),
                # Sorted, so the same export lists the same observations; permissions,
                # versions and conflicts above are derived from all of them.
                "definition_observations": observations[:_DEFINITION_SAMPLE],
                "definition_observations_omitted": max(0, len(observations) - _DEFINITION_SAMPLE),
                "definition_conflicts": conflicting,
                "installed_teams": team_names[:_TEAM_SAMPLE],
                "install_count": len(installs),
                "rsc_permissions": summarize_scopes(perms),
                "rsc_permission_basis": "definition-requested",
            }
        )
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
