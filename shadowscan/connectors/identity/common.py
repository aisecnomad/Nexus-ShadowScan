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
# One character, so a long run of separators is scanned in linear time; the
# rest of a run is stripped from the token before it.
_URL_LIST_SEPARATOR = re.compile(r"[,;](?=https?://)", re.I)
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


def app_product_or_hint(finding: Finding) -> bool:
    """Whether inventory should retain an established product or a provisional product name.

    This is a retention decision, never attribution: only established products
    enter frameworks/providers, and name-only observations remain correlated.
    The generic AI-name signature alone identifies no product.
    """
    return bool(
        finding.frameworks
        or finding.model_providers
        or finding.metadata.get("potential_frameworks")
        or finding.metadata.get("potential_providers")
    )


def merge_conflicting_app_attribution(target: Finding, observed: Finding) -> None:
    """Keep product observations and provisional names without selecting one app snapshot.

    Resource identity, ownership and enabled state remain unresolved. In
    particular, one snapshot's disabled flag cannot describe all observations.
    """
    for framework in observed.frameworks:
        target.add_framework(framework)
    for provider in observed.model_providers:
        target.add_model_provider(provider)
    for capability in observed.capabilities:
        target.add_capability(capability)
    for key in ("potential_frameworks", "potential_providers"):
        values = sorted(set(target.metadata.get(key, [])) | set(observed.metadata.get(key, [])))
        if values:
            target.metadata[key] = values
    for tag in observed.tags:
        if tag != "disabled":
            target.add_tag(tag)


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
    hyphens read as spaces; each signature still counts once. Names,
    publishers and descriptions are mutable metadata, never independent
    product attribution. A same-product domain, client id or scope can
    establish the product before its name is recorded as corroborated evidence.
    """
    finding.metadata["_app_assessment"] = True
    apply_matches(finding, domain_matches(index, *_url_hosts(urls)), weight_scale=0.8)
    if client_id:
        apply_matches(finding, index.match_client_id(client_id))
    classify_permissions(index, finding, scopes)
    apply_matches(finding, name_matches(index, name, *aliases, publisher, description), unverified_names=True)
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


def _url_hosts(urls: Iterable[str | None], *, split_lists: bool = True) -> list[str]:
    """The hostnames of the http(s) URLs in ``urls``, in order.

    OAuth reply/homepage URLs establish only their own hostname. A product
    domain in another site's path, query, fragment or userinfo is a mention,
    not corroboration of the app's product identity. A token with userinfo or
    a parser-differential character is skipped: a reply URL never carries
    credentials, and its host is not reliably the one a browser would use.
    With ``split_lists`` false each field is one URI (JWT issuer/audience),
    so embedded delimiters never create another endpoint to corroborate.
    """
    hosts: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url:
            continue
        for token in _url_tokens(url) if split_lists else [url]:
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


# The OpenID Connect Core scopes: they sign a user in and say nothing about
# what the app does with the session. Resource scopes that only look routine
# ("api", "full", "web", "workflow") are left out: they grant API or data
# access, which is a reason to report the app.
_OIDC_CORE_SCOPES: frozenset[str] = frozenset(
    {"openid", "profile", "email", "address", "phone", "offline_access"}
)
# The generic AI-name signature's words that are just as common in names that
# are not AI: an insurance or field agent, a CI build agent, a support
# assistant desk, a personal-finance "copilot", a chat bot integration. Its
# other terms (LLM, GPT, GenAI, "AI assistant", chatbot, RAG ...) and every
# product name, ambiguous ones such as Gemini included, are not.
_COMMON_AI_NAME_WORDS = frozenset({"agent", "agents", "assistant", "copilot", "bot"})
_COMMON_AI_NAME_WORD = re.compile(r"(?i)\b(?:agents?|assistant|copilot|bot)\b")
_GENERIC_AI_NAME = "identity-app.generic-ai-name"


def _common_words_only(index: SignatureIndex, names: Iterable[str | None]) -> bool:
    """Whether every name signature these texts match is the generic hint on a common word.

    The texts are matched again with those words removed, so a term the
    per-signal match quota left unread behind them (a "chatbot" after three
    common words) still counts as the stronger hint it is.
    """
    texts = [text for text in names if text]
    matches = [match for text in texts for match in index.match_name(text)]
    if any(
        match.signature_id != _GENERIC_AI_NAME or match.value.casefold() not in _COMMON_AI_NAME_WORDS
        for match in matches
    ):
        return False
    return not any(index.match_name(_COMMON_AI_NAME_WORD.sub(" ", text)) for text in texts)


def only_ai_name_hint(
    finding: Finding, scopes: Iterable[str], *, index: SignatureIndex, names: Iterable[str | None]
) -> bool:
    """Whether an app is a sign-in client with nothing that suggests AI, so it is not reported.

    True when every scope is an OpenID Connect Core scope and the app has no
    AI attribution at all: no product, provider, LLM-access or other policy
    tag, agent identity or registry record, and either no name hint or one
    that comes only from a common word (``_COMMON_AI_NAME_WORDS``) in
    ``names``, the texts the connector matched name signatures against.
    That is the decoy case: "Insurance Agent Desk" or "Copilot Money" with
    openid and profile, or a plain SSO app with nothing but those scopes.

    "LLM Gateway", "Company GPT", "AI Assistant" or an app named Gemini stays
    reported at the unattributed-app ceiling, as does any app holding a scope
    beyond those: a sign-in client is where an internal LLM front-end shows
    up, and the scanner must not hide it to look precise. Callers keep machine
    clients regardless.
    """
    if finding.frameworks or finding.model_providers:
        return False
    if set(finding.tags) - {"ai-name-hint"}:
        return False
    if any(str(scope).lower() not in _OIDC_CORE_SCOPES for scope in scopes if scope):
        return False
    return "ai-name-hint" not in finding.tags or _common_words_only(index, names)
