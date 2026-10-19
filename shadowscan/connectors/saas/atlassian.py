"""Atlassian Cloud (Jira / Confluence): user-installed Marketplace & Forge apps, Rovo agents.

Live: Universal Plugin Manager ``GET /rest/plugins/1.0/`` (site admin, basic auth with API token)
on the Jira site and, if configured, the Confluence site (``/wiki/rest/plugins/1.0/``).
Optionally Atlassian Admin API ``GET /admin/v1/orgs/{orgId}/...`` is not required.

Offline export: UPM ``plugins`` array (or a list of app objects with name / key / vendor).
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import app_product_or_hint, assess_app
from shadowscan.connectors.offline import OfflineInputBudget
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.identity import atlassian_site_origin
from shadowscan.utils.text import get_path

# Loader-assigned per-file scope for exports without a configured site. Any
# value an untrusted export supplies under this key is overwritten.
_UNRESOLVED_SCOPE_KEY = "_unresolved_scope"


class AtlassianConnector(BaseConnector):
    name: ClassVar[str] = "saas.atlassian"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "atlassian"
    description: ClassVar[str] = (
        "Marketplace / Forge apps installed on Jira & Confluence Cloud (AI assistants, Rovo agents, "
        "automation bots)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "site": (
            "concrete HTTPS site origin, e.g. https://<org>.atlassian.net "
            "(env ATLASSIAN_SITE; required for complete offline scans)"
        ),
        "email": "site admin email (env ATLASSIAN_EMAIL)",
        "api_token": "API token (env ATLASSIAN_API_TOKEN)",
        "products": "list of jira|confluence to query (default both)",
        "input": "offline: UPM plugins JSON",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        site = ctx.get("site", env="ATLASSIAN_SITE")
        self.site = atlassian_site_origin(site)
        if site not in (None, "") and self.site is None:
            raise ConnectorError("saas.atlassian: site must be a concrete HTTPS site origin without a path")
        # The same public plugin key in two unscoped exports must not merge
        # into one installation. Offline records are scoped per export file
        # (see _load_offline_file), so a directory holding several sites'
        # exports keeps them distinct; repeat scans of one file retain IDs.
        source = self.ctx.input_path
        self._unresolved_scope = self._scope_for(Path(str(source))) if source else secrets.token_hex(16)
        products = ctx.get("products") or ["jira", "confluence"]
        if isinstance(products, str):
            # A bare string would otherwise be iterated character by character.
            products = [item.strip() for item in products.split(",") if item.strip()]
        if (
            not isinstance(products, list)
            or not products
            or any(item not in {"jira", "confluence"} for item in products)
        ):
            raise ConnectorError("saas.atlassian: products must list only 'jira' and/or 'confluence'")
        self.products: list[str] = list(dict.fromkeys(products))

    def _scope_for(self, source: Path) -> str:
        resolved = source.expanduser().resolve()
        return hashlib.sha256(f"{self.name}\0{resolved}".encode()).hexdigest()[:32]

    def _load_offline_file(self, source: Path, budget: OfflineInputBudget) -> Iterator[dict[str, Any]]:
        scope = self._scope_for(source)
        for record in super()._load_offline_file(source, budget):
            record[_UNRESOLVED_SCOPE_KEY] = scope
            yield record

    @staticmethod
    def _is_error_record(data: dict[str, Any]) -> bool:
        # Atlassian can report failures through errorMessages while errors is
        # empty. An accompanying collection must not turn that into success.
        return BaseConnector._is_error_record(data) or bool(data.get("errorMessages"))

    def collect(self) -> Iterable[dict[str, Any]]:
        email = self.ctx.get("email", env="ATLASSIAN_EMAIL")
        token = self.ctx.get("api_token", env="ATLASSIAN_API_TOKEN")
        if not (self.site and email and token):
            raise ConnectorError("saas.atlassian: site, email and api_token required")
        http = HttpClient(self.site, auth=(email, token))
        for product in self.products:
            path = "/rest/plugins/1.0/" if product == "jira" else "/wiki/rest/plugins/1.0/"
            try:
                data = http.get_json(path, params={"os_authType": "basic"}) or {}
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                reason = str(exc.status) if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"saas.atlassian: {product} UPM not readable ({reason})")
                continue
            if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
                self.ctx.warn(f"saas.atlassian: {product} UPM returned an invalid collection")
                continue
            if self._is_error_record(data):
                self.ctx.warn(f"saas.atlassian: {product} UPM reported a provider error; coverage incomplete")
            for p in data["plugins"]:
                if not isinstance(p, dict):
                    self.ctx.warn(f"saas.atlassian: {product} UPM returned an invalid plugin entry")
                    continue
                p["_product"] = product
                p.pop(_UNRESOLVED_SCOPE_KEY, None)
                yield p

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        if self.site is None:
            self.ctx.warn(
                "saas.atlassian: site identity is unresolved; set verified site for offline input; "
                "coverage incomplete"
            )
        for p in records:
            if not self._valid_provider_record(p):
                self.ctx.warn("saas.atlassian: unsupported or malformed app record; coverage incomplete")
                continue
            if not p.get("userInstalled", True) and not p.get("_force"):
                continue
            self.ctx.examined()
            f = self._app_finding(p)
            if f:
                yield f

    def _valid_provider_record(self, p: Any) -> bool:
        if not self._record_fields_valid(
            p,
            strings=("name", "key", "description", "version", "_product"),
            mappings=("links",),
            arrays=("scopes",),
        ):
            return False
        vendor = p.get("vendor")
        return (
            bool((p.get("key") or p.get("name") or "").strip())
            and (
                vendor is None
                or isinstance(vendor, str)
                or self._record_fields_valid(vendor, strings=("name", "link"))
            )
            and self._record_fields_valid(p.get("links") or {}, strings=("self",))
            and all(isinstance(scope, str) for scope in (p.get("scopes") or []))
            and all(
                p.get(key) is None or isinstance(p[key], bool)
                for key in ("userInstalled", "enabled", "_force")
            )
        )

    def _record_scope(self, p: dict[str, Any]) -> str:
        scope = p.get(_UNRESOLVED_SCOPE_KEY)
        return scope if isinstance(scope, str) and scope else self._unresolved_scope

    def _app_finding(self, p: dict[str, Any]) -> Finding | None:
        name = p.get("name") or p.get("key")
        vendor = get_path(p, "vendor.name") or p.get("vendor")
        product = p.get("_product") or "jira"
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Atlassian app ({product}): {name}",
            resource=f"atlassian:{product}:app:{p.get('key') or name}",
            resource_type="atlassian-app",
            provider="atlassian",
            account=self.site,
            identity_discriminator=(
                "atlassian-app" if self.site else f"atlassian-app:unresolved:{self._record_scope(p)}"
            ),
            metadata={"identity_unresolved": True} if self.site is None else {},
        )
        assess_app(
            self.index,
            f,
            name=name,
            publisher=str(vendor) if vendor else None,
            description=" ".join(x for x in [p.get("description"), p.get("key")] if x),
            urls=[get_path(p, "vendor.link"), get_path(p, "links.self")],
            scopes=[s for s in (p.get("scopes") or []) if isinstance(s, str)],
        )
        if not app_product_or_hint(f):
            return None
        f.add_evidence(
            Evidence(
                signal="atlassian:app",
                description=(
                    f"{'Enabled' if p.get('enabled', True) else 'Disabled'} "
                    f"{'user-installed ' if p.get('userInstalled') else ''}app '{name}' ({p.get('key')}) by "
                    f"{vendor or 'unknown vendor'} v{p.get('version') or '?'}"
                ),
                weight=0.3,
            )
        )
        if p.get("enabled") is False:
            f.add_tag("disabled")
        f.metadata.update(
            {
                "key": p.get("key"),
                "vendor": vendor,
                "version": p.get("version"),
                "enabled": p.get("enabled"),
                "user_installed": p.get("userInstalled"),
                "product": product,
            }
        )
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
