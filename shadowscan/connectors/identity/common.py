"""Shared logic for identity-provider connectors."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit

from shadowscan.connectors.common import apply_matches, classify_permissions, domain_matches, name_matches
from shadowscan.models import Evidence, Finding, Kind
from shadowscan.signatures import SignatureIndex

# Redirect and homepage fields can hold several URLs separated by whitespace,
# commas or semicolons (a ServiceNow redirect_url, for example). A comma or
# semicolon separates only where a new http(s) URL starts (see _url_tokens).
_URL_LIST_SEPARATOR = re.compile(r"[,;]+(?=https?://)", re.I)
# A parsed hostname: a DNS name or an IP literal, nothing else.
_HOSTNAME = re.compile(r"[a-z0-9_.:-]+")
# A backslash or control character parses differently in Python and in
# browsers (WHATWG treats "\\" as a path separator), so such a token cannot
# establish the host a user is sent to.
_PARSER_DIFFERENTIAL = re.compile(r"[\\\x00-\x1f\x7f]")

MACHINE_GRANT_TYPES = {
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:device_code",
}


def assess_app(
    index: SignatureIndex,
    finding: Finding,
    *,
    name: str | None,
    publisher: str | None = None,
    description: str | None = None,
    urls: Iterable[str | None] = (),
    scopes: Iterable[str] = (),
    client_id: str | None = None,
    grant_types: Iterable[str] = (),
    auth_method: str | None = None,
    aliases: Iterable[str] = (),
) -> None:
    """Apply name / domain / scope / client-id signatures to an OAuth app finding.

    ``aliases`` are other spellings of the name, such as an app slug with its
    hyphens read as spaces; each signature still counts once.
    """
    finding.metadata["_app_assessment"] = True
    apply_matches(finding, domain_matches(index, *_url_hosts(urls)), weight_scale=0.8)
    if client_id:
        apply_matches(finding, index.match_client_id(client_id))
    apply_matches(finding, name_matches(index, name, *aliases, publisher, description))
    classify_permissions(index, finding, scopes)
    gts = {str(g).lower() for g in grant_types if g}
    if gts & MACHINE_GRANT_TYPES:
        finding.add_tag("machine-identity")
        finding.add_evidence(
            Evidence(
                signal="oauth:grant-type",
                description=f"Non-interactive grant types: {', '.join(sorted(gts & MACHINE_GRANT_TYPES))}",
                weight=0.4,
            )
        )
        if "urn:ietf:params:oauth:grant-type:token-exchange" in gts:
            finding.add_tag("delegation")
            finding.add_capability("delegated-identity")
    if auth_method and auth_method.lower() in {
        "private_key_jwt",
        "client_secret_jwt",
        "client_secret_post",
        "client_secret_basic",
    }:
        finding.metadata["token_endpoint_auth_method"] = auth_method


def _url_hosts(urls: Iterable[str | None]) -> list[str]:
    """The hostnames of the http(s) URLs in ``urls``, in order.

    OAuth reply/homepage URLs establish only their own hostname. A product
    domain in another site's path, query, fragment or userinfo is a mention,
    not corroboration of the app's product identity. A token with userinfo or
    a parser-differential character is skipped: a reply URL never carries
    credentials, and its host is not reliably the one a browser would use.
    """
    hosts: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url:
            continue
        for token in _url_tokens(url):
            if not token or _PARSER_DIFFERENTIAL.search(token):
                continue
            try:
                parsed = urlsplit(token if "://" in token else f"//{token}")
                host = parsed.hostname
                has_userinfo = parsed.username is not None or parsed.password is not None
            except ValueError:
                continue
            if parsed.scheme.lower() not in {"", "http", "https"} or not host or has_userinfo:
                continue
            if _HOSTNAME.fullmatch(host):
                hosts.append(host)
    return hosts


def _url_tokens(field: str) -> Iterator[str]:
    """Split a redirect or homepage field into URL tokens.

    Whitespace always separates: a URL never contains it. A comma or
    semicolon separates only where it is followed by a new ``http(s)://``
    URL, and never once the current token has reached its query or fragment,
    where both are ordinary characters: in ``https://a.example/cb?next=x,https://b.example``
    the second URL is query content of the first, not a host.
    """
    for chunk in field.split():
        start = 0
        for separator in _URL_LIST_SEPARATOR.finditer(chunk):
            token = chunk[start : separator.start()]
            if "?" in token or "#" in token:
                break
            yield token.strip(",;")
            start = separator.end()
        yield chunk[start:].strip(",;")


def identity_kind_for(*, user_consented: bool, machine: bool) -> Kind:
    if machine and not user_consented:
        return Kind.SERVICE_IDENTITY
    return Kind.OAUTH_GRANT


def summarize_scopes(scopes: Iterable[str], limit: int = 25) -> list[str]:
    out = sorted({str(s) for s in scopes if s})
    return out[:limit] + ([f"... +{len(out) - limit} more"] if len(out) > limit else [])
