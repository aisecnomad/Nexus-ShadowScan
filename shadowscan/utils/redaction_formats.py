"""Credentials recognizable by format: provider tokens, JWTs, keys and URLs.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. These rules need no context: a prefixed provider token, a JWT, a PEM
private key or an authorization scheme is withheld wherever it appears, and a
URL loses its userinfo, credential-bearing webhook path and sensitive query
fields.
"""

from __future__ import annotations

import contextvars
import re
from urllib.parse import unquote

from shadowscan.utils.redaction_assignments import _wordy
from shadowscan.utils.redaction_commands import _cli_option_mode
from shadowscan.utils.redaction_rules import (
    _KEY_NORMALISE,
    _REFERENCE,
    _VALUE_SEMICOLON,
    REDACTED,
    _credential_name,
    _kept_value,
    _redact_value,
    _sensitive_assignment_key,
    _setting_level,
)

# A token inside a longer identifier ('risk-assessment-2024') is not one, so a
# prefix needs a boundary before it. '\b' is too strict: 'n', 'D' and '_' are word
# characters, so it hid a token behind an escaped line break ('...key:\nsk-proj-...'
# in a trace or fixture), behind a percent escape ('?next=%2Fv1%3Fapi_key%3Dsk-proj-...')
# and behind an underscore ('cfg_sk-proj-...'). Those count as boundaries. A prefix that
# no ordinary word contains ('sk-proj-', 'ghp_', 'AKIA', JWT 'eyJ') also stands after a
# digit; the others keep the usual rule so a word or number that ends in their text
# ('disk-', 'task-', '2app-') is not read as a token.
#
# '\b' is also what keeps this fast: a lookbehind in front of the alternatives costs
# several times as much at every position of a large text. The tokens after a plain
# boundary are found by ``_SECRET_TOKEN``; the rest start at the character before them,
# which the regular expression reads first and the replacement keeps.
_ESCAPE = r"\\[nrt]|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}"
# The same boundaries as lookbehinds, for the JWT rule.
_ESCAPED_BOUNDARY = r"(?<=\\[nrt])|(?<=\\x[0-9A-Fa-f]{2})|(?<=\\u[0-9A-Fa-f]{4})|(?<=%[0-9A-Fa-f]{2})"
_SPECIFIC_TOKEN_START = r"(?:(?<![A-Za-z])|" + _ESCAPED_BOUNDARY + ")"
# Prefixes no ordinary word contains.
_SPECIFIC_TOKEN = (
    r"sk-(?:proj|ant|live|or-v1|lf|litellm|svcacct|admin)-[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    # GitLab personal/runner/trigger/deploy/feed/SCIM/CI/mail/OAuth/agent tokens.
    r"|gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-[A-Za-z0-9_-]{8,}|GR1348941[A-Za-z0-9_-]{20,}"
    r"|xox[abeprs]-[A-Za-z0-9-]{8,}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xapp-[A-Za-z0-9-]{8,}"
    # Google API keys, OAuth access/refresh tokens and OAuth client secrets.
    r"|AIza[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,}|1//0[A-Za-z0-9_-]{30,}|GOCSPX-[A-Za-z0-9_-]{20,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,}"
)
_GENERIC_TOKEN = (
    r"sk-[A-Za-z0-9_-]{8,}"
    r"|gsk_[A-Za-z0-9]{40,}|pcsk_[A-Za-z0-9_]{20,}|e2b_[a-f0-9]{40}|tgp_v1_[A-Za-z0-9_-]{30,}"
    r"|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|tvly-(?:dev-|prod-)?[A-Za-z0-9_-]{20,}"
    r"|xai-[A-Za-z0-9]{60,}|pplx-[A-Za-z0-9]{40,}|csk-[A-Za-z0-9]{30,}|nvapi-[A-Za-z0-9_-]{60,}"
    r"|r8_[A-Za-z0-9]{30,}|fc-[a-f0-9]{32}|app-[A-Za-z0-9]{24}|sk_[a-f0-9]{40,}"
    # Package registries, cloud platforms and developer SaaS.
    r"|npm_[A-Za-z0-9]{30,}|pypi-AgE[A-Za-z0-9_-]{40,}|do[opr]_v1_[a-f0-9]{64}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{24,}"
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|dapi[a-f0-9]{32}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"
    r"|ATATT3[A-Za-z0-9_=-]{40,}|lin_api_[A-Za-z0-9]{32,}|ntn_[A-Za-z0-9]{40,}"
    r"|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"
    r"|sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,}|glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}"
    r"|sntry[su]_[A-Za-z0-9+/=_-]{30,}|hv[sbr]\.[A-Za-z0-9_-]{24,}"
    r"|fw_(?=[A-Za-z]*\d)[A-Za-z0-9]{24,}"
    r"|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}"
)
# Keep this backstop aligned with detectable credential formats regardless of
# which signature packs the operator enables for discovery.
# ASCII boundaries: a token written directly after CJK or other non-Latin text is one.
_SECRET_TOKEN = re.compile(r"\b(?:" + _SPECIFIC_TOKEN + "|" + _GENERIC_TOKEN + r")\b", re.ASCII)
_UNDERSCORE_OR_ESCAPE_TOKEN = re.compile(
    r"(?P<glue>_|" + _ESCAPE + r")(?:" + _SPECIFIC_TOKEN + "|" + _GENERIC_TOKEN + r")\b"
)
_DIGIT_TOKEN = re.compile(r"(?P<glue>[0-9])(?:" + _SPECIFIC_TOKEN + r")\b")
# Webhook and bot endpoints whose *path* is the credential. The scheme, host
# and a fixed prefix are kept for context; the remainder of the path is
# withheld. Query parameters (e.g. Power Automate's ``sig``) are handled by the
# ordinary query-field rules.
_PATH_SECRET_RULES: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (
        re.compile(r"hooks\.slack(?:-gov)?\.com"),
        re.compile(r"/(?:services|workflows|triggers|actions|commands)/"),
    ),
    (re.compile(r"(?:(?:ptb|canary)\.)?discord(?:app)?\.com"), re.compile(r"/api(?:/v\d+)?/webhooks/")),
    (re.compile(r"(?:[a-z0-9-]+\.)*webhook\.office\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"outlook\.office(?:365)?\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"hooks\.zapier\.com"), re.compile(r"/hooks/")),
    (re.compile(r"hook\.(?:[a-z0-9-]+\.)?(?:make|integromat)\.com"), re.compile(r"/")),
    (re.compile(r"maker\.ifttt\.com"), re.compile(r"/trigger/[^/]+/(?:json/)?with/key/")),
    (re.compile(r"api\.telegram\.org"), re.compile(r"/(?:file/)?bot")),
    # n8n (commonly self-hosted, so any host): /webhook/<id> and /webhook-test/<id>.
    (re.compile(r".+"), re.compile(r"(?:/[^/]+)*?/webhook(?:-test|-waiting)?/")),
)
# A JWT starts at an 'eyJ' that follows the boundary rule above and runs to the end of
# its third dotted segment. Each attempt starts at a run of base64url characters and
# reads the characters before the first such 'eyJ' as 'lead', which is kept: an attempt
# from every 'eyJ' would read a run of 'eyJ-eyJ-eyJ-...' without dots once per 'eyJ',
# which takes quadratic time, and every run is read once here. Use ``_redact_jwts``.
_JWT_HEADER = r"(?=eyJ)" + _SPECIFIC_TOKEN_START + "eyJ"
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<lead>(?:(?!" + _JWT_HEADER + r")[A-Za-z0-9_-])*+)"
    r"(?P<jwt>" + _JWT_HEADER + r"[A-Za-z0-9_-]*+\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]*+)"
)
# Private key blocks, to the end of the text when unterminated: PEM ('BEGIN PRIVATE KEY',
# 'BEGIN OPENSSH PRIVATE KEY', PGP's '... PRIVATE KEY BLOCK'), RFC 4716's
# '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----' and a PuTTY key file, whose private part
# ends at its 'Private-MAC:' line.
_PEM = re.compile(
    r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY-----|\Z)"
    r"|---- BEGIN SSH2 (?:ENCRYPTED )?PRIVATE KEY ----.*?(?:---- END SSH2 (?:ENCRYPTED )?PRIVATE KEY ----|\Z)"
    r"|PuTTY-User-Key-File-[0-9]+:.*?(?:Private-MAC:[^\r\n]*|\Z)",
    re.DOTALL,
)
# OpenPGP's armored 'PRIVATE KEY BLOCK'. The established passes withhold it
# first, as they do a PEM key, wherever that shows nothing their order
# withholds (see redaction._withhold_key_blocks); otherwise every line from
# the block on is withheld.
_ADDED_PEM = re.compile(
    r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY BLOCK-----.*?"
    r"(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY BLOCK-----|\Z)",
    re.DOTALL,
)
# One character of the credential after an authorization scheme. It stops before
# glued text a later pass reads, so withholding the credential keeps the name that
# withholds the value after it ('v--token w', 'v=password: w'): a '--option' name,
# and a '=name' assignment (base64 padding is never followed by a letter). The run
# such a stop leaves after the marker is withheld last, unless it is one such name
# (see _withhold_scheme_tails).
_AUTH_CHAR_GUARD = r"(?!--)(?!=[A-Za-z])"
_AUTH_CHAR = r"(?:" + _AUTH_CHAR_GUARD + r"[A-Za-z0-9+/_.=-])"
_AUTH_NON_DIGIT = r"(?:" + _AUTH_CHAR_GUARD + r"[A-Za-z+/_.=-])"
# The credential after an authorization scheme. It is never '=' signs alone: after
# 'bearer =>', '=~' or '==' they are an operator's, and read as the credential
# they hid the operator from the assignment rules, which then showed the value.
# The possessive quantifier keeps the scan linear in the text.
_AUTH_CREDENTIAL = r"(?P<credential>(?!=++(?![A-Za-z0-9+/_.-]))" + _AUTH_CHAR + r"++)"
# 'Bearer token <credential>' names the scheme and then the word: the word is read
# as part of the scheme only when an opaque credential (16 or more characters with
# a digit) follows it, so prose such as 'a Bearer token is required' is unchanged.
# _redact_authorization then keeps a credential name followed by an assignment
# ('Bearer token postgres_password_1: v', or such a name on the next line): withheld
# here, it hid the name from the assignment rules, which then showed the value.
_AUTH_WORD = r"(?:(?P<word>token)(?P<gap>\s+)(?=" + _AUTH_CHAR + r"{16})(?=" + _AUTH_NON_DIGIT + r"*+[0-9]))?"
_AUTH = re.compile(r"(?i)\b(?P<scheme>Bearer|Basic|SSWS)\s+" + _AUTH_WORD + _AUTH_CREDENTIAL)
# A scheme after an escaped line break or a percent escape ('...header:\nBearer v') is read as well.
_ESCAPED_AUTH = re.compile(
    r"(?i)(?P<glue>" + _ESCAPE + r")(?P<scheme>Bearer|Basic|SSWS)\s+" + _AUTH_WORD + _AUTH_CREDENTIAL
)
# The glued run a guard stop leaves after the credential ('Bearer v--tail',
# 'Bearer v=x'), which the established rules matched with it (see
# _redact_authorization_established). The possessive quantifier keeps the scan
# linear in the text.
_GLUED = r"(?:--|=(?=[A-Za-z]))[A-Za-z0-9+/_.=-]*+"
_GLUED_RUN = re.compile(_GLUED)
_AUTH_GLUED = r"(?P<glued>" + _GLUED + r")?"
_AUTH_ESTABLISHED = re.compile(_AUTH.pattern + _AUTH_GLUED)
_ESCAPED_AUTH_ESTABLISHED = re.compile(_ESCAPED_AUTH.pattern + _AUTH_GLUED)
_ASSIGNED = re.compile(r"[ \t]*[:=]")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,20}://[^\s<>\"']+")
_QUERY_SEPARATOR = re.compile(r"[&#]")
_QUERY_TEXT = re.compile(r"\?[^\s<>\"']+")


def _redact_secret_tokens(text: str) -> str:
    """Withhold every provider token in ``text`` (see the boundary rules above)."""
    text = _SECRET_TOKEN.sub(REDACTED, text)
    text = _UNDERSCORE_OR_ESCAPE_TOKEN.sub(lambda match: match.group("glue") + REDACTED, text)
    return _DIGIT_TOKEN.sub(lambda match: match.group("glue") + REDACTED, text)


class _SchemeReading:
    """One reading of a text by the passes, as the scheme pass takes part in it.

    ``established``: the pass withholds the run glued after a credential with
    it, as the established rules did (see ``_redact_authorization_established``);
    otherwise the run stays for the other passes to read and goes last (see
    ``_withhold_scheme_tails``). ``glued``: a credential this reading met has
    such a run, so the two readings differ (see ``redaction.sanitize_text``).
    """

    def __init__(self, *, established: bool) -> None:
        self.established = established
        self.glued = False


# The reading the passes in progress take part in; none outside sanitize_text and
# sanitize, where the scheme pass reads as the established rules did.
_SCHEME_READING: contextvars.ContextVar[_SchemeReading | None] = contextvars.ContextVar(
    "_SCHEME_READING", default=None
)


def _redact_authorization(text: str) -> str:
    """Withhold the credential after an authorization scheme, keeping the scheme.

    The scheme's whitespace can span lines; keep them so excerpt lines stay aligned.
    The run a guard stop leaves after the credential stays in the text; the
    established reading withholds it here instead (see ``_SchemeReading``),
    and so does a call outside any reading, which no later step withholds
    the run for.
    """
    reading = _SCHEME_READING.get()
    if reading is None or reading.established:
        return _redact_authorization_established(text)

    def withheld(match: re.Match[str]) -> str:
        if _GLUED_RUN.match(match.string, match.end()):
            reading.glued = True
        credential = match.group("credential")
        if (
            match.group("word")
            and (_sensitive_assignment_key(credential) or _setting_level(credential))
            and _ASSIGNED.match(match.string, match.end())
        ):
            # 'Bearer token <name>: value': withhold the word as the credential and keep the
            # name, so the assignment rules still withhold the value after it.
            return match.group("scheme") + " " + REDACTED + match.group("gap") + credential
        return match.group("scheme") + " " + REDACTED + "\n" * match.group().count("\n")

    text = _AUTH.sub(withheld, text)
    return _ESCAPED_AUTH.sub(lambda match: match.group("glue") + withheld(match), text)


def _redact_authorization_established(text: str) -> str:
    """The scheme pass as the established rules ran it: a glued run goes with the credential.

    Kept only where it names a credential that a later pass reads ('--token v',
    '=password: v'), or after the 'token' word. A kept run joins the scheme's
    line, as those rules did; the lines of such a reading then no longer pair
    up with the text's (see ``redaction._merge_readings``).
    """

    def kept_glued(match: re.Match[str]) -> bool:
        glued = match.group("glued")
        if not glued:
            return False
        if glued.startswith("--"):
            name = glued.lstrip("-")
            return bool(
                name and not name.lower().startswith(("no-", "no_")) and _credential_name(name, numbered=True)
            )
        name = glued[1:]
        return bool(
            (_sensitive_assignment_key(name) or _setting_level(name))
            and _ASSIGNED.match(match.string, match.end())
        )

    def withheld(match: re.Match[str]) -> str:
        credential = match.group("credential")
        glued = match.group("glued") or ""
        if match.group("word"):
            if (_sensitive_assignment_key(credential) or _setting_level(credential)) and _ASSIGNED.match(
                match.string, match.end("credential")
            ):
                return match.group("scheme") + " " + REDACTED + match.group("gap") + credential + glued
            return match.group("scheme") + " " + REDACTED + "\n" * match.group().count("\n") + glued
        if kept_glued(match):
            return match.group("scheme") + " " + REDACTED + glued
        return match.group("scheme") + " " + REDACTED + "\n" * match.group().count("\n")

    text = _AUTH_ESTABLISHED.sub(withheld, text)
    return _ESCAPED_AUTH_ESTABLISHED.sub(lambda match: match.group("glue") + withheld(match), text)


# A scheme and the marker of its credential, as _redact_authorization leaves them.
_SCHEME_MARKER = r"(?:Bearer|Basic|SSWS) " + re.escape(REDACTED)
_NEXT_SCHEME_MARKER = re.compile(r"(?i)" + _SCHEME_MARKER)
# The run a guard stop leaves glued after a scheme credential's marker, with the
# scheme's line breaks between them ('Bearer [REDACTED]--tail', '...\\nSSWS
# [REDACTED]=x'), with or without the 'token' word, which the marker replaced.
# The run stops at the next scheme's marker ('v--tail-Bearer w'), whose own run
# is read next. The possessive quantifier keeps the scan linear in the text.
_SCHEME_TAIL = re.compile(
    r"(?i)(?P<head>"
    + _SCHEME_MARKER
    + r"\n*)(?P<glued>(?:--|=(?=[A-Za-z]))(?:(?!"
    + _SCHEME_MARKER
    + r")[A-Za-z0-9+/_.=-])*+)"
)
# A run that starts a line after a run that stays ('Bearer [REDACTED]--token\n=x
# ...'), read as a run that starts a line after the marker.
_LATER_RUN = re.compile(
    r"(?i)(?P<head>\n+)(?P<glued>(?:--|=(?=[A-Za-z]))(?:(?!" + _SCHEME_MARKER + r")[A-Za-z0-9+/_.=-])*+)"
)


# A run that starts a later line and holds no value: dashes or an '=' and at most
# one name of letters ('--verbose', '---', '=Section='). Only such a run is kept
# where removing it hides nothing (see redaction._without_later_line_runs).
_INERT_RUN = re.compile(r"(?:-++|=)(?:[A-Za-z]++(?:[-_.][A-Za-z]++)*+)?[-=]*+")
# A name of words, as a glued run must be to stay: no digit, so no token's tail.
_PLAIN_NAME = re.compile(r"[A-Za-z]+(?:[-_.][A-Za-z]+)*")
_SCHEME_WORDS = frozenset({"bearer", "basic", "ssws"})


def _glued_name_kept(glued: str, text: str, end: int) -> bool:
    """Whether the run glued after a scheme credential's marker is one name a pass reads.

    The run as a whole must be the name, made of words ('api-key', not
    'x9Kq2.pass'): a '--option' named for a credential or read by the option
    rules ('--token', '--auth', '--cookie'), or a '=name' named for a
    credential or a setting before an assignment's ':' or '=' ('=password:
    v'). It stays beside the value the pass withheld after it. Any other run
    is withheld whole, a name inside it included: by then every pass has
    read the run and withheld the value after such a name ('v=x--password
    w'), and the rest of the run can be the token's own tail ('v=x1=--abc=y2').
    ``end`` is where the run ends in ``text``.
    """
    option = glued.startswith("--")
    name = glued.lstrip("-") if option else glued[1:]
    if not _PLAIN_NAME.fullmatch(name) or not _wordy(re.sub(r"[-.]", "_", name)):
        return False
    if name.lower() in _SCHEME_WORDS:
        # The next scheme, glued on ('v----bearer Bearer w'): read as an option, it takes
        # that scheme's word as its value and leaves the credential after it.
        return False
    if option:
        return not name.lower().startswith(("no-", "no_")) and (
            _credential_name(name) or bool(_cli_option_mode(glued))
        )
    named = _sensitive_assignment_key(name) or _setting_level(name)
    return bool(named and _ASSIGNED.match(text, end))


def _withhold_scheme_tails(text: str, *, later_lines: bool = False) -> str:
    """Withhold the run glued after a scheme credential's marker, unless it is one name a pass reads.

    The credential stops before glued text ('Bearer v--tail', 'Bearer v=x'),
    and every other pass reads the run left after its marker as any other
    text: a name in it withholds the value after it ('v=x--password w'), and
    the assignment, URL and setting rules read on past it to values they
    withhold ('v=x=y\\npassword: w'). Withheld with the credential, the run hid
    that text from them, and they showed the value. So the run is withheld
    here, after all of them: ``sanitize_text`` runs this last, and ``sanitize``
    after it has also removed the known values from every field, so a value
    the run starts ('Bearer token v=x y' for a known 'x y') is still found
    whole. Both then read a text this changes once more (see
    ``redaction._without_glued_runs``). This step only removes text, so
    whatever the passes withhold stays withheld. Only a run that is one name
    a pass reads (see ``_glued_name_kept``) stays, beside the value it withheld.
    A run that starts the line after a run that stays is read as one that
    starts a line after the marker: kept, the name hid it from this step,
    and the value a pass reads once it goes ('Bearer v--token\\n=abc.def =
    password: w') was shown, and withheld only on the next sanitization.
    ``later_lines`` withholds only a run that starts a line after its
    marker's (see ``redaction._without_later_line_runs``).
    """
    if REDACTED not in text:
        return text

    def withheld(match: re.Match[str]) -> str:
        if _glued_name_kept(match.group("glued"), text, match.end()) or (
            later_lines
            and ("\n" not in match.group("head") or not _INERT_RUN.fullmatch(match.group("glued")))
        ):
            return match.group()
        if _NEXT_SCHEME_MARKER.match(text, match.end()):
            # The separators before the next scheme stay ('-Bearer [REDACTED]').
            glued = match.group("glued")
            return match.group("head") + glued[len(glued.rstrip("-+/.=")) :]
        return match.group("head")

    pieces: list[str] = []
    cursor = 0
    match = _SCHEME_TAIL.search(text)
    while match is not None:
        kept = withheld(match)
        pieces.extend((text[cursor : match.start()], kept))
        cursor = match.end()
        following = _LATER_RUN.match(text, cursor) if kept == match.group() else None
        match = following or _SCHEME_TAIL.search(text, cursor)
    pieces.append(text[cursor:])
    return "".join(pieces)


def _redact_jwts(text: str) -> str:
    """Withhold every JSON Web Token in ``text``, keeping what precedes its 'eyJ'."""
    if "eyJ" not in text:
        return text
    return _JWT.sub(lambda match: match.group("lead") + REDACTED, text)


def _url_host(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1 : host.find("]")] if "]" in host else host[1:]
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host.rstrip(".").lower()


def _redact_path_secret(host: str, path: str) -> str:
    """Withhold the credential-bearing remainder of a known webhook path.

    Idempotent: an already withheld path is returned unchanged.
    """
    if not host or not path:
        return path
    for host_rx, prefix_rx in _PATH_SECRET_RULES:
        if not host_rx.fullmatch(host):
            continue
        prefix = prefix_rx.match(path)
        if prefix and prefix.end() < len(path):
            return path[: prefix.end()] + REDACTED
    return path


# 'host', 'host:8080', '[::1]:8080': an authority that cannot hold a password.
_HOST_PORT = re.compile(r"(?:\[[^\]\s]*\]|[^\s:@\[\]]+)(?::[0-9]*)?")
_TEMPLATE_PORT = re.compile(r"\{[^{}\s]*\}")


def _reads_as_userinfo(authority: str) -> bool:
    """Whether the text before the first '/', '?' or '#' is 'user:password' cut short by one of them.

    'host', 'host:8080' and '[::1]:8080' are authorities that end there. So are
    a templated port ('${HOST}:${PORT}'), an empty authority ('file:///') and an
    authority without a colon (a token alone cannot be told from a host).
    """
    if not authority or _HOST_PORT.fullmatch(authority):
        return False
    _, colon, secret = authority.partition(":")
    return bool(colon and secret) and not (_REFERENCE.fullmatch(secret) or _TEMPLATE_PORT.fullmatch(secret))


def _authority_end(rest: str) -> int:
    """Where the authority of the URL text after '://' ends.

    That is the first '/', '?' or '#', since an '@' in a path or query value must not be
    mistaken for a hostname separator. A password may hold those characters raw
    ('postgres://u:example#pw@h', 'https://svc:example7?x@gw.example/v1'): when what comes
    first reads as 'user:password', the userinfo runs to the last '@' that is followed
    by a host and optional port, as far as the URL text goes. Every step is a single scan.
    """
    end = min((pos for c in "/?#" if (pos := rest.find(c)) >= 0), default=len(rest))
    if "@" in rest[:end] or not _reads_as_userinfo(rest[:end]):
        return end
    at = rest.rfind("@")
    if at < end:
        return end
    host_end = min((pos for c in "/?#" if (pos := rest.find(c, at)) >= 0), default=len(rest))
    return host_end if _HOST_PORT.fullmatch(rest, at + 1, host_end) else end


def _sanitize_url(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, rest = url.split("://", 1)
    authority_end = _authority_end(rest)
    authority, tail = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    path_end = min((pos for c in "?#" if (pos := tail.find(c)) >= 0), default=len(tail))
    tail = _redact_path_secret(_url_host(authority), tail[:path_end]) + tail[path_end:]
    url = scheme + "://" + authority + tail

    # Consume each field once. A regex that retries an unbounded key after every
    # '?' takes quadratic time on a URL containing many '?' and no '='. Keep '?'
    # within values (it is legal there) so redacting a secret never retains its
    # suffix. Fragment parameters receive the same protection as query fields.
    start = min((pos for c in "?&#" if (pos := url.find(c)) >= 0), default=len(url))
    if start == len(url):
        return url
    parts = [url[: start + 1]]
    cursor = start + 1
    for separator in _QUERY_SEPARATOR.finditer(url, cursor):
        parts.append(_query_value(url[cursor : separator.start()]))
        parts.append(separator.group(0))
        cursor = separator.end()
    parts.append(_query_value(url[cursor:]))
    return "".join(parts)


# The scheme of a URL inside the text of another (see ``_redact_nested_urls``).
_NESTED_SCHEME = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{0,20}://")


def _redact_nested_urls(text: str) -> str:
    """Read each URL inside the text of another URL as a URL (see ``_sanitize_url``).

    A URL runs to the first blank or quote, so one after a ',', a ';' or
    '?next=' is part of the URL before it ('redis://:pw@a,redis://:pw@b',
    'https://a/login?next=https://u:secret@b'), and the established pass reads
    the first authority alone. Each inner URL is read as far as the next one,
    which keeps the scan linear.
    """

    def nested(match: re.Match[str]) -> str:
        url = match.group(0)
        schemes = list(_NESTED_SCHEME.finditer(url, url.index("://") + 3))
        if not schemes:
            return url
        pieces = [url[: schemes[0].start()]]
        for scheme, following in zip(schemes, [*schemes[1:], None], strict=True):
            inner = url[scheme.start() : following.start() if following else len(url)]
            pieces.append(_URL.sub(_sanitize_url, inner))
        return "".join(pieces)

    return _URL.sub(nested, text) if "://" in text else text


def _query_value(field: str, *, bare: bool = False) -> str:
    """Withhold a credential-named query field; bare query text uses explicit names.

    Generic key/code parameters need a full URL context. Signature and
    credential-specific names also identify a secret in a relative URL or
    copied query string, without guessing whether arbitrary prose is a URL.
    """
    key, equals, value = field.partition("=")
    if not equals:
        return field
    decoded = unquote(key).lower()
    sensitive = _sensitive_assignment_key(decoded) or decoded in {
        "sig",
        "signature",
        "x-amz-signature",
        "x-goog-signature",
        "x-amz-security-token",
        "auth",
        "pwd",
        "pat",
    }
    if not bare:
        sensitive = sensitive or decoded in {"key", "code"}
    return key + equals + (REDACTED if sensitive else value)


def _redact_query_text(text: str) -> str:
    """Withhold explicit credential fields in scheme-less URLs and query excerpts."""

    def replace(match: re.Match[str]) -> str:
        query = match.group()
        pieces = ["?"]
        cursor = 1
        for separator in _QUERY_SEPARATOR.finditer(query, cursor):
            pieces.extend((_query_value(query[cursor : separator.start()], bare=True), separator.group()))
            cursor = separator.end()
        pieces.append(_query_value(query[cursor:], bare=True))
        return "".join(pieces)

    return _QUERY_TEXT.sub(replace, text) if "?" in text else text


# Cookie headers hold several ``name=value`` pairs separated by ';', any of
# which can be a session credential and may be quoted (sid="v"), so the whole
# header value is withheld, to the end of the line. A header may follow a JSON
# string escape ('\\r\\nCookie: ...'). The pass runs after the statement
# rules: a value they already withheld as a quoted marker that a ',', ')',
# ']' or '}' then ends is an argument ('get(url, cookie=session_cookie,
# timeout=5)'), and what follows it is the next argument, not another cookie.
_COOKIE_HEADER = re.compile(
    r"(?i)(?:(?<![\w.-])|(?<=\\[nrtbf])|(?<=\\u[0-9a-f]{4}))(?P<key>set-cookie2?|cookie2?)"
    r"(?P<sep>[ \t]*[:=][ \t]*)(?=\S)"
)
_LINE_END = re.compile(r"[\r\n]")
_COOKIE_ARGUMENT = re.compile(r"(?P<quote>[\"'])\[REDACTED\](?P=quote)[ \t]*[,)\]}]")
_ALPHANUMERIC_TEXT = re.compile(r"[A-Za-z0-9]")
# ``api-key:value`` with no space (an HTTP header written inline). Limited to
# these header and field names: a suffix rule would also rewrite identifiers
# such as ``example-credential:provider.openai`` or ``arn:...:secret:name``.
_COMPACT_HEADER_NAMES = frozenset(
    {
        "apikey",
        "xapikey",
        "xgoogapikey",
        "ocpapimsubscriptionkey",
        "xauthtoken",
        "xaccesstoken",
        "xapitoken",
        "authorization",
        "proxyauthorization",
        "password",
        "passwd",
    }
)
_COMPACT_COLON = re.compile(r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*):(?=[^\s\"'\\])")
# The letters of a JSON string escape that ends the text before a name
# ('\\npassword:v', '\\r\\nX-Api-Key:v', '\\u000apassword:v'). The key above
# starts at the escape's letter, since a backslash may precede a name.
_ESCAPE_LETTERS = re.compile(r"[nrtbf]|u[0-9A-Fa-f]{4}")
# A ``${NAME}`` reference is one unit of the value, so a placeholder is read
# whole and kept; its content is a name, so a failed read stops at once.
_COMPACT_VALUE = re.compile(
    r"\[REDACTED\]|(?:\$\{[A-Za-z0-9_.:-]*+\}|[^\s,;\}\]\)\"'])+"
    r"(?:" + _VALUE_SEMICOLON + r"(?:\$\{[A-Za-z0-9_.:-]*+\}|[^\s,;\}\]\)\"'])*)*"
)
# Report identifiers the gateway connector writes in place of a caller key.
_OPAQUE_IDENTITY = re.compile(r"(?:credential|caller):(?:hmac-)?sha256:[a-f0-9]{64}")


def _quoted_context(text: str, position: int) -> bool:
    """Whether the name at ``position`` sits inside a quoted string (its opening quote precedes it)."""
    return position > 0 and text[position - 1] in "\"'"


def _redact_cookie_headers(text: str) -> str:
    """Withhold whole ``Cookie`` and ``Set-Cookie`` header values (see ``_COOKIE_HEADER``).

    Runs after the statement rules. After '=', an argument they already
    withheld ends the argument (see ``_COOKIE_ARGUMENT``) and the rest of its
    line is read for another header ('get(u, cookie=c, timeout=5) Cookie: ...');
    any other value is withheld to the end of its line. The marker stays bare
    after '=' (the statement rules, run again once this pass changed the text,
    quote it where it is an argument) and is quoted after a colon, unless it
    sits inside a quoted string, so the mapping rules read one scalar.
    """
    if "ookie" not in text and "OOKIE" not in text and "ookie" not in text.lower():
        return text
    out: list[str] = []
    pos = 0
    while (match := _COOKIE_HEADER.search(text, pos)) is not None:
        start = match.end()
        assigned = "=" in match.group("sep")
        if assigned:
            argument = _COOKIE_ARGUMENT.match(text, start)
            if argument is not None:
                out.append(text[pos : argument.end()])
                pos = argument.end()
                continue
        line_end = _LINE_END.search(text, start)
        end = len(text) if line_end is None else line_end.start()
        raw = text[start:end]
        bare = raw.rstrip(" \t")
        out.append(text[pos:start])
        if _ALPHANUMERIC_TEXT.search(bare.replace(REDACTED, "")) is None:
            out.append(raw)  # already withheld: only markers and punctuation are left
        else:
            quoted = not assigned and not _quoted_context(text, match.start("key"))
            out.append(('"' + REDACTED + '"' if quoted else REDACTED) + raw[len(bare) :])
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _redact_compact_colons(text: str) -> str:
    """Withhold ``api-key:value`` (no space) after a credential header or field name."""
    pieces: list[str] = []
    cursor = 0
    position = 0
    while match := _COMPACT_COLON.search(text, position):
        position = match.end()
        key = match.group("key")
        name = _KEY_NORMALISE.sub("", key.lower())
        if name not in _COMPACT_HEADER_NAMES and match.start() and text[match.start() - 1] == "\\":
            escape = _ESCAPE_LETTERS.match(key)
            if escape is not None:
                name = _KEY_NORMALISE.sub("", key[escape.end() :].lower())
        if name not in _COMPACT_HEADER_NAMES:
            continue
        value = _COMPACT_VALUE.match(text, position)
        if value is None:
            continue
        # Escaped JSON (\"api-key:S\") leaves the delimiter's backslash behind.
        raw = value.group(0)
        bare = raw.rstrip("\\")
        if (
            not bare
            or bare == REDACTED
            or _OPAQUE_IDENTITY.fullmatch(bare)
            or _OPAQUE_IDENTITY.fullmatch(key + ":" + bare)
            or _kept_value(bare)
            or _redact_value(bare) == bare
        ):
            position = value.end()
            continue
        # Inside a quoted string (a curl header, a JSON value) the marker stays
        # bare so the string keeps its delimiters; elsewhere it is quoted so
        # the mapping-value rules read it as one scalar.
        withheld = REDACTED if _quoted_context(text, match.start("key")) else '"' + REDACTED + '"'
        pieces.append(text[cursor:position])
        pieces.append(withheld + raw[len(bare) :])
        cursor = position = value.end()
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)
