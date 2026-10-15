"""Generic SaaS app-inventory connector (offline exports from any admin console or CASB).

Feed it a CSV / JSON export of installed apps, OAuth grants or integrations from a
platform ShadowScan has no native connector for (Google Workspace Marketplace, HubSpot,
Box, Dropbox, Salesforce AppExchange, Okta Integration Network reports, Netskope /
Zscaler / Microsoft Defender for Cloud Apps discovered-app exports...). Column
names are mapped through ``fields``; sensible defaults cover common exports.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import config_boolean, finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.redaction import sanitize

DEFAULT_FIELDS: dict[str, list[str]] = {
    "name": [
        "name",
        "app",
        "app_name",
        "application",
        "app name",
        "application name",
        "display_name",
        "displayName",
        "title",
        "integration",
        "product",
    ],
    "id": ["id", "app_id", "client_id", "clientId", "application_id", "appId", "key"],
    "publisher": ["publisher", "vendor", "developer", "company", "owner_org", "provider"],
    "description": ["description", "category", "categories", "summary", "notes"],
    "url": ["url", "homepage", "website", "domain", "domains", "redirect_uri", "redirect_uris", "app_url"],
    "scopes": ["scopes", "scope", "permissions", "permission", "oauth_scopes", "access", "granted_scopes"],
    "users": ["users", "user_count", "num_users", "installs", "install_count", "seats", "user"],
    "owner": [
        "owner",
        "installed_by",
        "requested_by",
        "admin",
        "installer",
        "created_by",
        "user_email",
        "email",
    ],
    "installed_at": ["installed_at", "created_at", "date", "first_seen", "install_date", "granted_at"],
    "last_used": ["last_used", "last_used_at", "last_activity", "last_seen", "updated_at"],
    "status": ["status", "state", "approval", "sanctioned", "risk", "risk_score"],
}


def _scope_values(value: Any) -> list[str]:
    return (
        [str(scope) for scope in value if scope not in (None, "")]
        if isinstance(value, list)
        else [scope.strip() for scope in re.split(r"[,;\s]+", str(value or "")) if scope.strip()]
    )


class GenericSaaSConnector(BaseConnector):
    name: ClassVar[str] = "saas.generic"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "saas"
    description: ClassVar[str] = (
        "Offline app-inventory export from any SaaS admin console or CASB (column mapping via `fields`)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": "CSV / JSON export (required)",
        "platform": (
            "label for the platform the export came from (e.g. 'google-marketplace', 'hubspot', "
            "'defender-mcas')"
        ),
        "fields": "optional column mapping {name: 'App Name', scopes: 'Permissions', ...}",
        "keep_all": "emit every app, not only AI / privileged matches (default false)",
    }
    offline_formats: ClassVar[str] = "CSV / JSON"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.platform = str(ctx.get("platform") or "saas")
        self.keep_all = config_boolean(ctx.get("keep_all", False), "keep_all")
        user_fields = ctx.get("fields") or {}
        self.fields = {
            k: ([user_fields[k]] if k in user_fields else []) + v for k, v in DEFAULT_FIELDS.items()
        }

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError("saas.generic: offline only; set 'input' to an export file")

    def _candidate_values(self, rec: dict[str, Any], key: str) -> list[Any]:
        aliases = {str(candidate).casefold() for candidate in self.fields[key]}
        return [
            value
            for raw_key, value in rec.items()
            if str(raw_key).casefold() in aliases and value not in (None, "")
        ]

    def _get(self, rec: dict[str, Any], key: str) -> Any:
        values = self._candidate_values(rec, key)
        if values:
            return values[0]
        return None

    def _has_ambiguous_aliases(self, rec: dict[str, Any]) -> bool:
        for key in self.fields:
            values = self._candidate_values(rec, key)
            if len(values) < 2:
                continue
            first = values[0]
            if any(type(value) is not type(first) or value != first for value in values[1:]):
                return True
        return False

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        analysed = unnamed = 0
        for rec in records:
            self.ctx.examined()
            if self._has_ambiguous_aliases(rec):
                self.ctx.warn("saas.generic: skipped a record with ambiguous field aliases")
                continue
            analysed += 1
            name = self._get(rec, "name")
            if not isinstance(name, str) or not name.strip():
                # Blank spreadsheet rows carry no app and need no diagnostic;
                # every other unnamed record is a coverage gap.
                if any(str(value).strip() for value in rec.values() if value is not None):
                    unnamed += 1
                else:
                    analysed -= 1
                continue
            try:
                f = self._finding(rec)
            except (
                AttributeError,
                TypeError,
                ValueError,
                KeyError,
                RecursionError,
                MatchTimeoutError,
            ) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"saas.generic: skipped a malformed app record ({type(exc).__name__}){detail}")
                continue
            if f:
                yield f
        # An export whose columns map to no app name must not look like an
        # inventory without AI apps. Name the accepted columns, never values.
        if unnamed and unnamed == analysed:
            self.ctx.warn(
                "saas.generic: no record has an app name; expected a column named one of "
                f"{', '.join(str(alias) for alias in self.fields['name'])} (or map one with fields.name)"
            )
        elif unnamed:
            self.ctx.warn(f"saas.generic: skipped {unnamed} of {analysed} records without an app name")

    def _finding(self, rec: dict[str, Any]) -> Finding | None:
        name = self._get(rec, "name")
        if not isinstance(name, str) or not name.strip():
            # A missing display field may hide an AI signature. It is not
            # evidence that the exported app is outside the scan's scope.
            self.ctx.warn("saas.generic: app record has no valid name; coverage incomplete")
            return None
        # Credential context must survive field selection, before splitting,
        # joining or truncating can hide a known secret. Match this safe view
        # too: a credential's contents cannot establish product/permission
        # evidence. Preserve the original resource only for its identity digest.
        _, safe_values = sanitize((rec, [(self._get(rec, key),) for key in self.fields]))
        safe = {key: value for key, (value,) in zip(self.fields, safe_values, strict=True)}
        # JSON exports may carry non-string list members; coerce rather than crash.
        scopes = _scope_values(safe["scopes"])
        urls = safe["url"]
        url_list = (
            [str(u) for u in urls if u not in (None, "")]
            if isinstance(urls, list)
            else [u.strip() for u in re.split(r"[,;\s]+", str(urls or "")) if u.strip()]
        )
        app_id = self._get(rec, "id")
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.OAUTH_GRANT if scopes else Kind.BOT_APP,
            title=f"{self.platform} app: {safe['name']}",
            resource=f"{self.platform}:app:{app_id or name}",
            resource_type="saas-app",
            provider=self.platform,
            owner=str(safe["owner"] or "") or None,
            first_seen=str(safe["installed_at"] or "") or None,
            last_seen=str(safe["last_used"] or "") or None,
        )
        assess_app(
            self.index,
            f,
            name=str(safe["name"]),
            publisher=str(safe["publisher"] or "") or None,
            description=str(safe["description"] or "") or None,
            urls=url_list,
            scopes=scopes,
            client_id=str(safe["id"]) if safe["id"] else None,
        )
        interesting = bool(f.frameworks) or any(t.startswith("policy.") for t in f.tags)
        if not interesting and not self.keep_all:
            return None
        users = safe["users"]
        try:
            user_count = (
                int(str(users).replace(",", ""))
                if users is not None and str(users).replace(",", "").isdigit()
                else None
            )
        except ValueError:
            user_count = None
        f.add_evidence(
            Evidence(
                signal=f"{self.platform}:app",
                description=(
                    f"'{safe['name']}' from {self.platform} export; status {safe['status'] or 'n/a'}; "
                    f"users {user_count if user_count is not None else users or '?'}; scopes "
                    f"{', '.join(scopes)[:300] or 'n/a'}"
                ),
                weight=0.2 + (min(0.2, user_count / 500) if user_count else 0),
            )
        )
        f.metadata.update(
            {
                "platform": self.platform,
                "status": safe["status"],
                "users": user_count if user_count is not None else users,
                "scopes": summarize_scopes(scopes),
            }
        )
        finalize(f, self.index)
        f.sanitize(credential_context=rec)
        return f
