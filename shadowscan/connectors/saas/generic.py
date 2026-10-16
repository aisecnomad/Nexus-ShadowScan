"""Generic SaaS app-inventory connector (offline exports from any admin console or CASB).

Feed it a CSV / JSON export of installed apps, OAuth grants or integrations from a
platform ShadowScan has no native connector for (Google Workspace Marketplace, HubSpot,
Box, Dropbox, Salesforce AppExchange, Okta Integration Network reports, Netskope /
Zscaler / Microsoft Defender for Cloud Apps discovered-app exports...). Column
names are mapped through ``fields``; sensible defaults cover common exports.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import config_boolean, finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.credential_identity import credential_identity_scope, keyed_credential_digest
from shadowscan.utils.redaction import REDACTED, _sensitive_key, sanitize

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


# Report sanitization withholds a whole field that contains a known credential
# shorter than this, rather than replacing the credential (see utils.redaction).
_SHORT_CREDENTIAL_CHARS = 8
# A short value in a credential column that is a flag, not a secret: a yes/no or
# not-applicable word, or at most one letter or digit ('N', '-', '1', '****').
_FLAG = re.compile(r"(?i)[\W_]*[^\W_]?[\W_]*|y(?:es)?|no?|true|false|on|off|n/?a|nil")
# A whole value that stands in for a credential: a lowercase 'your_...' name, an
# identifier in angle brackets or '${...}', a placeholder word, or a run of x or *.
# Stricter than connectors.common._PLACEHOLDER, which also takes 'your' followed by
# letters in any case and any text in '<...>' or '${...}': a client secret such as
# 'YourOrgProdSecretKey' or '<Xk9#mP2$qL7vB>' is a credential, not a placeholder.
_WHOLE_PLACEHOLDER = re.compile(
    r"your[_-][a-z_]+|<[A-Za-z_][A-Za-z0-9_.-]*>|\$\{[A-Za-z_][A-Za-z0-9_]*\}"
    r"|(?i:x{3,}|\*{3,}|changeme|redacted|placeholder|todo|null|none)"
)
# The fields besides the name that signature matching reads (see ``assess_app``):
# one that a credential withholds entirely can no longer show the AI app it names.
_MATCHED_FIELDS = ("publisher", "description", "url", "scopes", "id")


def _numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _credential_text(value: Any, copies: set[str]) -> Any:
    """A number under a credential name as the text sanitization learns; any other value as it is.

    Sanitization learns text only, so a JSON number ('"password": 48213977') was
    never removed from the fields that copy it, while the same row as CSV was.
    Its text is learned like any other credential's, and, since sanitization
    leaves numbers as they are, a field holding the same number is withheld as
    a short credential's copy is (``copies``), unless it is a flag ('0', '1').
    """
    if not _numeric(value):
        return value
    text = str(value)
    if not _FLAG.fullmatch(text):
        copies.add(text)
    return text


def _left_out(value: Any, copies: set[str]) -> bool:
    """Whether a value under a credential name stays out of the credential context.

    A placeholder as a whole value ('none', '****', 'xxxxxxxx', 'changeme',
    'your_secret', '<secret>', '${SECRET}'; see ``_WHOLE_PLACEHOLDER``) is not
    a secret. A value shorter than eight characters is not learned either:
    sanitization would withhold each field containing it, and exports fill
    such columns with flags ('N', '-', 'Yes'). Unless it is a flag, it is added
    to ``copies``, and a field equal to it is withheld. Every other value is
    learned whatever it looks like: a word such as 'test', 'demo', 'here' or
    'Your', a run of x or * beside other text, or a sequence such as
    'Abcd1234' does not make it a placeholder (``looks_like_placeholder``
    suppresses detections; it cannot tell a credential column's secret from an
    example).
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if _WHOLE_PLACEHOLDER.fullmatch(text):
        return True
    if len(text) >= _SHORT_CREDENTIAL_CHARS:
        return False
    if not _FLAG.fullmatch(text):
        copies.add(text)
    return True


def _credential_context(item: Any, copies: set[str], credential: bool = False) -> Any:
    """``item`` as credential context, without the values under credential names that are not learned.

    Sanitization learns every value under a credential name and removes it from
    the other fields; one shorter than eight characters withholds each field
    that contains it. Exports often fill such columns with a flag or a
    placeholder, which would then erase app names, dates and identities while
    protecting nothing. Those values are left out (see ``_left_out``, which
    collects the short ones that are not flags in ``copies``); every other one
    is learned, a number as its text (``_credential_text``).
    """
    if isinstance(item, Mapping):
        kept: dict[Any, Any] = {}
        for key, value in item.items():
            named = credential or _sensitive_key(str(key))
            if named:
                value = _credential_text(value, copies)
            if not (named and _left_out(value, copies)):
                kept[key] = _credential_context(value, copies, named)
        return kept
    if isinstance(item, (list, tuple)):
        members = [_credential_text(value, copies) for value in item] if credential else list(item)
        return [
            _credential_context(value, copies, credential)
            for value in members
            if not (credential and _left_out(value, copies))
        ]
    return item


def _without_copies(value: Any, copies: set[str]) -> Any:
    """``value`` with each text or number equal to a short credential in ``copies`` withheld."""
    if isinstance(value, str):
        return REDACTED if value.strip() in copies else value
    if _numeric(value):
        return REDACTED if str(value) in copies else value
    if isinstance(value, Mapping):
        return {key: _without_copies(member, copies) for key, member in value.items()}
    if isinstance(value, (list, tuple)):
        return [_without_copies(member, copies) for member in value]
    return value


def _withheld(raw: Any, clean: Any) -> bool:
    """Whether sanitization left nothing of a nonblank ``raw`` text but markers and punctuation."""
    return clean != raw and not any(character.isalnum() for character in str(clean).replace(REDACTED, ""))


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
        # evidence. The resource is sanitized with the same context.
        app_id = self._get(rec, "id")
        raw_resource = f"{self.platform}:app:{app_id or name}"
        copies: set[str] = set()
        context = _credential_context(rec, copies)
        raw = {key: self._get(rec, key) for key in self.fields}
        selected = raw
        if copies:
            # A short credential is not learned, but a field equal to one is withheld,
            # and so is an ID equal to one in the resource.
            selected = {key: _without_copies(value, copies) for key, value in raw.items()}
        shown_resource = f"{self.platform}:app:{selected['id'] or selected['name']}"
        _, safe_values = sanitize((context, [(value,) for value in selected.values()] + [(shown_resource,)]))
        safe = {key: value for key, (value,) in zip(self.fields, safe_values[:-1], strict=True)}
        (resource,) = safe_values[-1]
        if _withheld(name, safe["name"]):
            # Nothing of the name is left to match: an AI app could be hidden here.
            self.ctx.warn(
                "saas.generic: a credential in an app record withheld its name; coverage incomplete"
            )
            return None
        hidden = [key for key in _MATCHED_FIELDS if raw[key] is not None and _withheld(raw[key], safe[key])]
        if hidden:
            # A publisher, description, URL, scope or ID equal to a credential no longer
            # names the app it may identify as an AI product: the record is still read,
            # but the scan cannot claim it found every AI app ('OpenAI' as both vendor and
            # API key reported nothing). The warning names fields, never values.
            self.ctx.warn(
                "saas.generic: a credential in an app record withheld its "
                f"{', '.join(hidden)}; coverage incomplete"
            )
        # JSON exports may carry non-string list members; coerce rather than crash.
        scopes = _scope_values(safe["scopes"])
        urls = safe["url"]
        url_list = (
            [str(u) for u in urls if u not in (None, "")]
            if isinstance(urls, list)
            else [u.strip() for u in re.split(r"[,;\s]+", str(urls or "")) if u.strip()]
        )
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.OAUTH_GRANT if scopes else Kind.BOT_APP,
            title=f"{self.platform} app: {safe['name']}",
            resource=resource,
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
        f.sanitize(credential_context=context)
        if f.resource != raw_resource:
            # A public digest of the raw resource would let a reader confirm a
            # guessed credential offline. Keep redacted resources distinct with
            # a keyed pseudonym instead: scan-local unless the operator's
            # SHADOWSCAN_IDENTITY_KEY is set (metadata.identity_scope).
            pseudonym = keyed_credential_digest(raw_resource)
            f.id = "ss-" + hashlib.sha256(f"{f.compute_id()}|{pseudonym}".encode()).hexdigest()[:16]
            f.update_metadata(identity_scope=credential_identity_scope())
        return f
