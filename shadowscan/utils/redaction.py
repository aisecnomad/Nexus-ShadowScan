"""Credential-safe evidence and report values.

Sanitize *before* shortening excerpts: once a credential is truncated, its
recognizable structure can be lost. These helpers deliberately do not depend on
signature settings; disabling secret discovery must never disable redaction.

The passes live in the ``redaction_*`` modules beside this one:
``redaction_rules`` (shared names, limits and value tests),
``redaction_formats`` (token formats and URLs), ``redaction_statements``
(tokenized source assignments), ``redaction_assignments`` (assignments,
mappings and defaults in text), ``redaction_calls``, ``redaction_commands``
and ``redaction_markup``. This module drives them and is their one public
face: every name they define reads through it, and a name replaced here (by a
test's monkeypatch, for example) is replaced in every module that binds it,
exactly as when all of them lived in this one module.

Patch and replace rules through this module, never through a ``redaction_*``
module: a name set on one of those changes only that module, and every other
module that imported the name silently keeps the old object.
"""

from __future__ import annotations

import datetime
import decimal
import re
import sys
import types
import uuid
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from shadowscan.utils import (
    redaction_assignments,
    redaction_calls,
    redaction_commands,
    redaction_entropy,
    redaction_formats,
    redaction_markup,
    redaction_rules,
    redaction_statements,
)
from shadowscan.utils.credential_identity import keyed_credential_digest
from shadowscan.utils.redaction_assignments import (
    _redact_connection_passwords,
    _redact_fallback_defaults,
    _redact_line_tails,
    _redact_mapping_values,
    _redact_netrc_entries,
    _redact_opaque_assignments,
    _redact_plain_assignments,
    _redact_rc_credentials,
    _redact_yaml_multiline_values,
)
from shadowscan.utils.redaction_calls import _redact_auth_pairs, _redact_credential_calls
from shadowscan.utils.redaction_commands import (
    _aws_configure_argv_secret_indices,
    _redact_aws_configure,
    _redact_command_credentials,
    _redact_environment_commands,
    _redact_extended_options,
    _redact_opaque_options,
    _redact_user_secrets,
)
from shadowscan.utils.redaction_formats import (
    _ADDED_PEM,
    _GLUED_RUN,
    _PEM,
    _SCHEME_READING,
    _URL,
    _later_line_runs,
    _redact_authorization,
    _redact_compact_colons,
    _redact_cookie_headers,
    _redact_jwts,
    _redact_nested_urls,
    _redact_query_text,
    _redact_secret_tokens,
    _sanitize_url,
    _SchemeReading,
    _withhold_scheme_tails,
)
from shadowscan.utils.redaction_markup import (
    _redact_flow_records,
    _redact_markup_credentials,
    _redact_markup_settings,
    _redact_name_value_pairs,
    _redact_record_settings,
    _redact_reversed_records,
)
from shadowscan.utils.redaction_rules import (
    _FINGERPRINT,
    _KEY_NORMALISE,
    _MAX_REDACTION_WORK,
    _MAX_SANITIZATION_CHARS,
    _MAX_SANITIZATION_NODES,
    REDACTED,
    SanitizationLimitError,
    _credential_literal,
    _credential_name,
    _redact_value,
    _sensitive_assignment_key,
    _sensitive_flag,
    _sensitive_key,
    _sensitive_name,
    _setting_level,
    _setting_value_withheld,
)
from shadowscan.utils.redaction_statements import _redact_python_assignments

# Values the sanitizer descends into; sets and frozensets are traversed like lists.
_CONTAINERS = (Mapping, list, tuple, set, frozenset)
_T = TypeVar("_T")

# Keys whose mapping or list of name/value records holds environment variables.
_ENVIRONMENT_KEYS = frozenset({"env", "environment", "environment_variables", "environmentvariables"})
# A credential container can include descriptive fields as well as secret
# material. Its descriptor values are not credentials merely because they
# occur next to one (for example {"provider": "openai", "value": "..."}).
_CREDENTIAL_DESCRIPTORS = frozenset(
    {"id", "objectid", "name", "type", "provider", "scope", "scopes", "status"}
)
# Descriptors that are opaque secret material inside a container named for
# credentials ('credentials.id'), but name an identity elsewhere ('api_key.id').
_CREDENTIAL_GROUP_IDS = frozenset({"id", "objectid"})
# An 'auth' block ('{"auth": {"type": "bearer", "value": "..."}}') holds its
# credential under a generic field name; 'auth' alone is too broad a key to
# withhold whole, so only these generic credential fields inside it are.
_AUTH_CONTAINER_KEYS = frozenset({"auth", "authentication", "authn"})
_AUTH_VALUE_KEYS = frozenset({"value", "key", "credential"})


# Leaves that keep their type: JSON's scalars and the standard library's, whose text is
# bounded by their type. Any other leaf (bytes, a set, an exception, a plugin's object)
# reaches a report through ``json.dumps(default=str)`` or ``repr`` as it is, so it is
# turned into text first (see ``_plain``).
_SCALARS = (bool, int, float, datetime.date, datetime.time, datetime.timedelta, decimal.Decimal, uuid.UUID)
_PLAIN_TYPES = (str, Mapping, list, tuple, *_SCALARS)
# The exact scalar types a sanitize pass leaves, which are also what the surrender
# path's detached copy shares without running subclass code (#264): a subclass of one
# (an IntEnum, a numpy scalar, a datetime subclass) is rebuilt as its standard type.
# ``datetime`` is a ``date`` to isinstance, so it is listed too, or every exact
# datetime would be rebuilt on every pass.
_SCALAR_TYPES = frozenset((*_SCALARS, datetime.datetime))


class _Copy(dict[str, Any]):
    """A mapping a ``sanitize`` reading copied, with a copy of every member of its source.

    Two keys can read alike once withheld ('SSWS a--auth' and 'SSWS b' are
    both 'SSWS [REDACTED]' in one reading, and not in the other). As a dict,
    the copy is what the reading always made: each step that copies it keeps
    one member per key, at the place of the first and with the value of the
    last, as a dict built from the members the step before kept does.
    ``view`` holds the members it keeps, in that order. ``members`` also
    holds the others, copied by every step as well, one for each member of
    the source mapping in its order: the two readings then pair up member by
    member wherever their keys read alike (see ``_merge_mappings``). Copies
    are equal only when all their members and views are. ``sanitize``
    returns plain dicts (see ``_dicts``).
    """

    __slots__ = ("members", "view")

    def __init__(self, members: list[tuple[str, Any]], view: list[int]) -> None:
        super().__init__(members[index] for index in view)
        self.members = members
        self.view = view

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _Copy):
            return self.view == other.view and self.members == other.members
        return dict.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self == other

    __hash__ = None


def _all_members(item: Mapping) -> list[tuple[Any, Any]]:
    """The members of ``item``: of a copy, one for each member of its source (see ``_Copy``)."""
    return item.members if isinstance(item, _Copy) else list(item.items())


def _copied(source: Mapping, members: list[tuple[str, Any]]) -> _Copy:
    """``members``, a copy of each of ``_all_members(source)`` in its order, as a copy of ``source``.

    As a dict it keeps what a dict built from the members ``source`` shows
    as a dict keeps (see ``_Copy``).
    """
    view: list[int] = []
    places: dict[str, int] = {}
    for index in source.view if isinstance(source, _Copy) else range(len(members)):
        key = members[index][0]
        place = places.get(key)
        if place is None:
            places[key] = len(view)
            view.append(index)
        else:
            view[place] = index
    return _Copy(members, view)


def _dicts(item: Any) -> Any:
    """``item``, a copy ``sanitize`` made, with plain dicts in place of its copies (see ``_Copy``)."""
    if isinstance(item, Mapping):
        return {key: _dicts(child) for key, child in item.items()}
    if isinstance(item, (list, tuple)):
        members = [_dicts(child) for child in item]
        return tuple(members) if isinstance(item, tuple) else members
    return item


def _member_order(member: Any) -> tuple[str, str]:
    try:
        return type(member).__name__, repr(member)
    except Exception:  # noqa: BLE001 - an arbitrary object's own repr may raise anything
        return type(member).__name__, ""


def _plain(item: Any) -> Any:
    """``item`` as a value ``sanitize`` can read and copy.

    Text, mappings, lists, tuples and the scalars above are returned as they are; a
    scalar's subclass is rebuilt as the exact standard type (``_exact_scalar``), so an
    overrun scan's surrender keeps the finding a completed run reports (#264). Bytes
    become text (undecodable bytes are replaced), a set a list in a stable order, and
    any other object, an exception included, its ``str`` -- which ``sanitize`` then
    reads like any other text.
    """
    if item is None or isinstance(item, _PLAIN_TYPES):
        if isinstance(item, _SCALARS) and type(item) not in _SCALAR_TYPES:
            return _exact_scalar(item)
        return item
    if isinstance(item, (bytes, bytearray, memoryview)):
        if len(item) > _MAX_SANITIZATION_CHARS:
            raise SanitizationLimitError("text sanitization size limit exceeded")
        return bytes(item).decode("utf-8", errors="replace")
    if isinstance(item, (set, frozenset)):
        return sorted(item, key=_member_order)
    try:
        return str(item)
    except Exception:  # noqa: BLE001 - an arbitrary object's own __str__ may raise anything
        return f"<{type(item).__qualname__}>"


def _exact_scalar(item: Any) -> Any:
    """A standard scalar's subclass as the exact parent type, with the value a report shows.

    The supervisor's detached copy shares a leaf only at its exact type, so no
    subclass code runs on its thread; rebuilding here, on the worker, keeps the
    finding where the old copy omitted it at surrender (#264). ``bool`` cannot
    be subclassed. An ``int`` or ``float`` is read through the base type's own
    slot, which returns the stored value a report shows and runs no override of
    ``__int__`` or ``__float__``. Any other subclass is rebuilt from its fields
    and kept only when it reads as the original does: one whose fields do not
    build its base (pandas ``NaT``) or that carries more than its base keeps (a
    nanosecond pandas ``Timestamp``) becomes its text, which is what a report
    showed through ``default=str``. The rebuilt ``datetime`` and ``time`` keep
    their ``tzinfo`` and ``fold`` as an exact instance does.
    """
    if isinstance(item, int):
        return int.__int__(item)
    if isinstance(item, float):
        return float.__float__(item)
    try:
        text = str(item)
    except Exception:  # noqa: BLE001 - a subclass's own __str__ may raise anything
        return f"<{type(item).__qualname__}>"
    try:
        rebuilt = _rebuilt_scalar(item)
    except Exception:  # noqa: BLE001 - a subclass's fields may not build its base type
        return text
    return rebuilt if str(rebuilt) == text else text


def _rebuilt_scalar(item: Any) -> Any:
    """``item``, a date, time, timedelta, Decimal or UUID subclass, rebuilt from its fields."""
    if isinstance(item, datetime.datetime):
        return datetime.datetime(
            item.year, item.month, item.day, item.hour, item.minute, item.second,
            item.microsecond, item.tzinfo, fold=item.fold,
        )  # fmt: skip
    if isinstance(item, datetime.date):
        return datetime.date(item.year, item.month, item.day)
    if isinstance(item, datetime.time):
        return datetime.time(
            item.hour, item.minute, item.second, item.microsecond, item.tzinfo, fold=item.fold
        )
    if isinstance(item, datetime.timedelta):
        return datetime.timedelta(item.days, item.seconds, item.microseconds)
    if isinstance(item, decimal.Decimal):
        return decimal.Decimal(item)
    return uuid.UUID(int=item.int)


def credential_id(value: Any) -> str:
    """Keyed credential pseudonym, stable only within the active private-key scope.

    Legacy public SHA-256 identifiers are rekeyed when passed here. Already
    keyed identifiers remain idempotent so sanitized evidence can be replayed.
    """
    s = str(value)
    if s.startswith("credential:hmac-sha256:") and _FINGERPRINT.fullmatch(s):
        return s
    return "credential:hmac-sha256:" + keyed_credential_digest(s)


def sanitize_text(text: str) -> str:
    """Redact recognizable credentials, assignments, auth headers and URL secrets.

    Context-named values are also withheld: XML elements and attributes,
    name/value records, command-line options, environment commands, basic
    authentication pairs, literals passed to credential-named callees and
    literal fallback defaults of credential names.

    The established passes run first, with the rules and in the order they
    had before the extended passes were added; the extended passes then read
    what they leave. Each pass reads the text the passes before it leave, so
    a rule that withheld more in an early pass would change what the later
    passes see: a value withheld together with the name glued after it
    ('v#password = ...') hides that name from the assignment rules, and the
    credential after the name is no longer withheld. Run last, an added rule
    only adds markers, and whatever the established passes withhold stays
    withheld. The runs glued after a scheme credential's marker go after
    every pass, since the passes read them (see ``_without_glued_runs``).

    A text with such a run is read twice: so, and as the established rules
    read it, withholding the run with its credential in the scheme pass (see
    ``_SchemeReading``); neither reading withholds all that the other does.
    Each reading is read again as the next sanitizations would read it, until
    it stays the same (see ``_settled``), since evidence is sanitized more
    than once; each line then shows only what both settled readings show (see
    ``_merge_readings``).

    A text where no credential stops at such a run is read as the established
    rules read it. The step that withholds the runs then finds only runs that
    start a line after their scheme's ('Bearer v\\n--verbose'). Runs that are
    only a name or a separator stay unless removing them lets the passes
    withhold more (see ``_without_later_line_runs``); any other run, which
    holds a value ('--max-time=30'), is withheld. A marker shows where a run
    was withheld (see ``_marked_later_lines``), as in a text with a glued run.
    """
    text = _checked_text(text)
    reading = _SchemeReading(established=False)
    first = _in_reading(reading, lambda: _redact_extended(_sanitize_established(text)))
    shown = _in_reading(reading, lambda: _without_glued_runs(first))
    if not reading.glued:
        return first if shown == _without_later_line_runs(first) else _marked_later_lines(first, shown)
    plain = _settled(
        shown,
        lambda again: _in_reading(
            _SchemeReading(established=False),
            lambda: _without_glued_runs(_redact_extended(_established_passes(again))),
        ),
    )
    established = _in_reading(
        _SchemeReading(established=True),
        lambda: _settled(
            _redact_extended(_sanitize_established(text)),
            lambda again: _redact_extended(_established_passes(again)),
        ),
    )
    return _merge_readings(plain, established)


def sanitize_excerpt(value: Any, limit: int = 200) -> Any:
    """A text ``value`` redacted whole, then shortened to ``limit`` characters.

    Shortening first can cut a credential away from what identifies it (a URL password from
    its '@', a value from its name), and the later report sanitizer then sees an ordinary
    string. Text beyond the sanitizer's safety limits is withheld entirely. Anything other
    than text is returned unchanged for the report sanitizer.
    """
    if not isinstance(value, str):
        return value
    try:
        text = sanitize_text(value)
    except SanitizationLimitError:
        return REDACTED
    return text if len(text) <= limit else text[: limit - 1] + "…"


def sanitize_text_excerpt(value: str | None, limit: int = 200) -> str | None:
    """``sanitize_excerpt`` of a provider record's text field, which must be text or absent.

    Any other value (a list, a number) raises TypeError, as the ``truncate`` it replaces did,
    so the connector rejects the record as malformed and coverage is incomplete, instead of
    reporting the raw value in place of a shortened summary.
    """
    if value is not None and not isinstance(value, str):
        raise TypeError("provider text field is not a string")
    excerpt: str | None = sanitize_excerpt(value, limit)
    return excerpt


# How often a reading of a text with a glued run is read again (see _settled).
_GLUED_READINGS_AGAIN = 4


def _settled(first: _T, again: Callable[[_T], _T]) -> _T:
    """``first``, read ``again`` until a reading changes nothing, at most ``_GLUED_READINGS_AGAIN`` times.

    A later sanitization can withhold more of a reading than the reading
    itself did ('--a=:v' once the run before it is withheld), and evidence is
    sanitized more than once on its way to a report. Each reading only adds
    markers, so the last one withholds whatever any earlier one did.
    """
    current = first
    for _ in range(_GLUED_READINGS_AGAIN):
        following = again(current)
        if following == current:
            break
        current = following
    return current


def _in_reading(reading: _SchemeReading, read: Callable[[], _T]) -> _T:
    """``read()``, with the scheme pass taking part in ``reading`` (see ``_SchemeReading``)."""
    token = _SCHEME_READING.set(reading)
    try:
        return read()
    finally:
        _SCHEME_READING.reset(token)


def _merge_readings(plain: str, established: str) -> str:
    """Two readings of one text, each line as withheld as both withhold it.

    A text with a run glued after a scheme credential is read with the run
    and without it (see ``sanitize_text``). The run is text the passes read:
    with it, a name in it withholds the value after it ('v=x--password w');
    without it, a value it hid from the assignment rules ('v=x = password:
    w') is read. Every pass keeps the lines of a text, so the two readings
    are compared line by line (see ``_merged_line``). The established rules
    joined a line kept after a scheme to the scheme's line; readings whose
    lines do not pair up withhold the whole text, keeping its line breaks.

    So each line of the result shows only what the same line of each
    reading shows: the result shows nothing either reading withholds.
    """
    if plain == established:
        return plain
    plain_lines, established_lines = plain.split("\n"), established.split("\n")
    if len(plain_lines) != len(established_lines):
        return REDACTED + "\n" * plain.count("\n")
    return "\n".join(
        _merged_line(one, other) for one, other in zip(plain_lines, established_lines, strict=True)
    )


def _merged_line(plain: str, established: str) -> str:
    """One line of two readings, showing nothing either withholds (see ``_merge_readings``).

    Where one line shows only what the other shows (see ``_shows_within``),
    that one is kept; otherwise the whole line is withheld. Where the plain
    reading removed the run that starts the established line ('--verbose x'
    after a scheme credential's line), a marker shows where it was.
    """
    if plain == established or _shows_within(established, plain):
        run = established[: len(established) - len(plain)]
        if run and established.endswith(plain) and _GLUED_RUN.fullmatch(run):
            return REDACTED + plain
        return plain
    if _shows_within(plain, established):
        return established
    return REDACTED + "\r" * plain.endswith("\r")


def _shows_within(kept: str, shown: str) -> bool:
    """Whether ``shown`` is ``kept`` with spans withheld or removed, and nothing more.

    Each piece ``shown`` shows between its markers occurs in ``kept``, in
    order and without overlapping, so every character it shows ``kept``
    shows as well.
    """
    position = 0
    for piece in shown.split(REDACTED):
        found = kept.find(piece, position)
        if found < 0:
            return False
        position = found + len(piece)
    return True


# How often the text left once the glued runs go is read again (see _without_glued_runs).
_GLUED_RUN_READINGS = 3


def _without_glued_runs(text: str) -> str:
    """``text``, which every pass has read, without the runs glued after scheme credentials.

    The passes read each run as text (see ``_withhold_scheme_tails``), so
    they can also read it as part of what follows: '<token>=abc.def =
    password: v' is an assignment to 'abc.def', and 'password: v' is not
    read. Without the run, the text says 'password: v' plainly. So a text
    the step changes is read once more by every pass, as the next
    sanitization would read it, and its runs go again. Each reading only
    adds markers and each step only removes text, so the result withholds
    whatever any reading withholds.

    A chain of lines that each start with a run loses one run per reading
    (see ``_withhold_scheme_tails``). A text still changing after
    ``_GLUED_RUN_READINGS`` readings loses the rest of each chain at once and
    is read once more, then its runs go again: kept as the last reading left
    it, without one run more, it showed the value the last run had hidden
    ('Bearer v\\n--r0\\n--r0\\n--r0\\n=abc.def = password: w'), or, after a fifth
    run, every value of the chain.
    """
    for _ in range(_GLUED_RUN_READINGS):
        cut = _withhold_scheme_tails(text)
        if cut == text:
            return text
        text = _redact_extended(_established_passes(cut))
    cut = _withhold_scheme_tails(text, chains=True)
    if cut == text:
        return text
    return _withhold_scheme_tails(_redact_extended(_established_passes(cut)), chains=True)


def _without_later_line_runs(text: str) -> str:
    """``text`` without the runs that ``_without_glued_runs`` removes from the start of a later line.

    Where no credential stopped at a run, the established rules read the
    text as its first reading does and showed the runs that start the lines
    after a scheme credential's. If ``_without_glued_runs`` only removed
    such runs and no pass then withheld more, it gives this text, and the
    first reading, which shows those runs besides, is kept. No pass reads
    this text, so each chain of such runs goes in one scan, however long.
    """
    for _ in range(_GLUED_RUN_READINGS + 1):
        cut = _withhold_scheme_tails(text, later_lines=True, chains=True)
        if cut == text:
            break
        text = cut
    return text


def _marked_later_lines(first: str, shown: str) -> str:
    """``shown``, ``first`` without its runs, with a marker where a run that started a line was.

    A run that starts a line after a scheme credential's marker (see
    ``_later_line_runs``) and that its line in ``shown`` no longer starts
    with was withheld; the line then starts with a marker, unless it already
    does, as ``_merged_line`` marks it in a text with a glued run. Every pass
    keeps the lines of a text, so the lines of ``first`` and ``shown`` pair up.
    """
    runs = _later_line_runs(first)
    lines = shown.split("\n")
    if not runs or len(lines) != first.count("\n") + 1:
        return shown
    for index, run in runs.items():
        if not lines[index].startswith((run, REDACTED)):
            lines[index] = REDACTED + lines[index]
    return "\n".join(lines)


def _marked_copy(first: Any, shown: Any) -> Any:
    """``shown``, ``first`` without its runs, with each text marked as ``_marked_later_lines`` marks it.

    ``shown`` is ``_without_scheme_tails(first)``: the two hold the same
    members (see ``_Copy``), and a mapping keeps those its dict keeps.
    """
    if isinstance(shown, str):
        return _marked_later_lines(first, shown) if isinstance(first, str) else shown
    if isinstance(shown, Mapping) and isinstance(first, Mapping):
        members, shown_members = _all_members(first), _all_members(shown)
        view = shown.view if isinstance(shown, _Copy) else range(len(shown_members))
        marked: dict[str, Any] = {}
        for index in view:
            (key, child), (shown_key, shown_child) = members[index], shown_members[index]
            marked[_marked_copy(key, shown_key)] = _marked_copy(child, shown_child)
        return marked
    if isinstance(shown, (list, tuple)) and type(first) is type(shown):
        items = [_marked_copy(one, other) for one, other in zip(first, shown, strict=True)]
        return tuple(items) if isinstance(shown, tuple) else items
    return _dicts(shown)


def _checked_text(text: str) -> str:
    """``text`` as a string within the sanitization size limit."""
    if not isinstance(text, str):
        # Untyped callers still pass bytes-like values.
        text = str(text)  # type: ignore[unreachable]
    if len(text) > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("text sanitization size limit exceeded")
    return text


def _redact_extended(text: str, *, reread: bool = False) -> str:
    """The rules added to the established passes, on the text those leave (see ``sanitize_text``).

    Settings in markup and name/value records (hierarchical and
    credential-like names), 'dotnet user-secrets set', numbered names and
    YAML values under credential-like names, and opaque values of options
    named for a credential. The options come last: withheld earlier, a value
    glued to a following name ('--key v#openaiKey = ...') would hide that
    name from the others. Only the netrc and Yarn 1 rc credentials, whose
    names no other rule reads, come after them. URLs inside another URL's
    text are read after all of them, and a text they change is then read once
    more, as the next sanitization would read it (``reread``).
    """
    text = _redact_markup_settings(text)
    text = _redact_record_settings(text)
    text = _redact_user_secrets(text)
    text = _redact_connection_passwords(text)
    text = _redact_opaque_assignments(text, extended=True)
    text = _redact_fallback_defaults(text, extended=True)
    text = _redact_reversed_records(text)
    text = _redact_query_text(text)
    text = _redact_extended_options(text)
    # A cookie header comes before the compact names: the rest of its line
    # holds the other cookies, past any ';' the others stop at.
    headers = _redact_cookie_headers(text)
    compact = _redact_compact_colons(headers)
    reshaped = compact != text
    text = _redact_aws_configure(_redact_opaque_options(compact))
    # Literals and a comment after a credential's value end come next: the
    # passes above decide where each value ends.
    text = _redact_line_tails(text)
    # netrc entries and Yarn 1 settings part a credential from its name by
    # blanks alone, which no rule above reads; read last, they only add markers.
    text = _redact_netrc_entries(_redact_rc_credentials(text))
    # A bare marker that these passes leave after a sensitive key's colon
    # ('api_key : <opaque>') is read by the established mapping pass as the start
    # of a mapping value; normalize it here so that sanitizing again changes nothing.
    result = _redact_mapping_values(text) if REDACTED in text else text
    if reshaped:
        # A cookie header withheld to the end of its line, or a withheld
        # 'name:value', changes the statement around it for the statement rules:
        # 'get(url, cookie=a; b=v' loses the ';' that ended the argument, and
        # 'api_key:a=1; sid=v' becomes 'api_key:"[REDACTED]"; sid=v', an
        # annotation they read on past the ';'; a bare marker left in an
        # argument ('get(url, cookie=[REDACTED]') is one they quote. What they
        # would change there on the next sanitization is changed now.
        result = _redact_mapping_values(_redact_python_assignments(result))
    # An inner URL's userinfo or query field, withheld only here, changes the
    # URL the established passes read; they read the text once more.
    nested = _redact_nested_urls(result)
    if nested == result or reread:
        return nested
    return _redact_extended(_established_passes(nested), reread=True)


def _sanitize_established(text: str) -> str:
    """The established passes, in their order and with their rules (see ``sanitize_text``).

    Armored PGP private key blocks are withheld next to the PEM keys, before
    any pass reads a name (see ``_withhold_key_blocks``).
    """
    text = _PEM.sub(_withheld_block, _checked_text(text))
    blocks = list(_ADDED_PEM.finditer(text))
    return _withhold_key_blocks(text, blocks) if blocks else _established_passes(text)


def _withheld_block(match: re.Match[str]) -> str:
    """The marker for a private key block, keeping its line breaks so excerpt lines stay aligned."""
    return REDACTED + "\n" * match.group(0).count("\n")


def _withhold_key_blocks(text: str, blocks: list[re.Match[str]]) -> str:
    """The established passes on ``text``, with its armored PGP private key ``blocks`` withheld first.

    A credential name before a block ('private_key: -----BEGIN PGP ...')
    made the established rules withhold its BEGIN line, and the extended
    rule that withholds a block starts at that line: the key's body on the
    lines after it was shown. Withheld before every name pass, as a PEM key
    is, the whole block goes and the name before it stays. A value that
    starts inside a block and runs past its END line ('password: "...' in
    the block, closed on a later line), though, is withheld by the
    established order and was shown once the block went first. So the
    blocks go first only where no line outside them then shows anything the
    established order withholds (see ``_shows_no_more``). Otherwise the
    text every pass leaves in the established order is kept up to the line
    of the first block, and every line from there on is withheld; the
    established passes then read that text once more, as the next
    sanitization would.
    """
    pieces: list[str] = []
    cursor = 0
    for block in blocks:
        pieces.append(text[cursor : block.start()])
        pieces.append(_withheld_block(block))
        cursor = block.end()
    pieces.append(text[cursor:])
    first = _established_passes("".join(pieces))
    kept = _redact_extended(_established_passes(text))
    if _shows_no_more(text, blocks, kept, _redact_extended(first)):
        return first
    lines = kept.split("\n")
    if len(lines) != text.count("\n") + 1:
        return REDACTED + "\n" * text.count("\n")
    start = text.count("\n", 0, blocks[0].start())
    return _established_passes("\n".join([*lines[:start], REDACTED, *[""] * (len(lines) - start - 1)]))


def _shows_no_more(text: str, blocks: list[re.Match[str]], kept: str, shown: str) -> bool:
    """Whether ``shown`` shows nothing that ``kept`` withholds outside the ``blocks`` of ``text``.

    Every pass keeps the lines of a text, so the two are compared line by
    line. The lines inside a block are withheld in ``shown``. Any other line
    must be its line in ``kept`` with at most one more span withheld: the
    text before one of its markers starts ``kept``'s line and the text after
    that marker ends it. The marker of a block is on its first line, so the
    start of its last line, where the rest of the block was, counts as one.
    The blanks and carriage return that end a line are not compared: the
    block's marker keeps only the line feeds of the CRLF breaks inside it,
    and a mapping value withheld in ``kept`` keeps the blanks after it.
    """
    kept_lines, shown_lines = kept.split("\n"), shown.split("\n")
    if not len(kept_lines) == len(shown_lines) == text.count("\n") + 1:
        return False
    inside: set[int] = set()
    ends: set[int] = set()
    line = position = 0
    for block in blocks:
        line += text.count("\n", position, block.start())
        last = line + block.group().count("\n")
        inside.update(range(line + 1, last))
        if last > line:
            ends.add(last)
        line, position = last, block.end()
    return all(
        index in inside
        or _line_shows_no_more(kept_line.rstrip(" \t\r"), shown_line.rstrip(" \t\r"), end=index in ends)
        for index, (kept_line, shown_line) in enumerate(zip(kept_lines, shown_lines, strict=True))
    )


def _line_shows_no_more(kept: str, shown: str, *, end: bool) -> bool:
    """Whether ``shown`` is ``kept`` with at most one more span withheld (see ``_shows_no_more``).

    ``end`` counts the start of ``shown`` as a marker.
    """
    if kept == shown:
        return True
    limit = min(len(kept), len(shown))
    head = _common_length(lambda size: kept[:size] == shown[:size], limit)
    tail = _common_length(lambda size: kept[len(kept) - size :] == shown[len(shown) - size :], limit)
    markers = [(0, 0)] if end else []
    found = shown.find(REDACTED)
    while found >= 0:
        markers.append((found, found + len(REDACTED)))
        found = shown.find(REDACTED, found + len(REDACTED))
    return any(
        before <= head and len(shown) - after <= tail and before + len(shown) - after <= len(kept)
        for before, after in markers
    )


def _common_length(equal: Callable[[int], bool], limit: int) -> int:
    """The largest size up to ``limit`` for which ``equal`` holds, if it holds for every smaller one."""
    low, high = 0, limit
    while low < high:
        middle = (low + high + 1) // 2
        if equal(middle):
            low = middle
        else:
            high = middle - 1
    return low


def _established_passes(text: str) -> str:
    """The established passes that follow the private keys, in their order (see ``_sanitize_established``)."""
    text = _URL.sub(_sanitize_url, text)
    text = _redact_markup_credentials(text)
    text = _redact_flow_records(text, quoted_only=True)
    text = _redact_name_value_pairs(text)
    text = _redact_command_credentials(text)
    text = _redact_environment_commands(text)
    text = _redact_auth_pairs(text)
    text = _redact_credential_calls(text)
    text = _redact_python_assignments(text)
    text = _redact_yaml_multiline_values(text)
    text = _redact_mapping_values(text)
    text = _redact_opaque_assignments(text)
    text = _redact_jwts(text)
    text = _redact_secret_tokens(text)
    text = _redact_authorization(text)
    # Fallback defaults come after plain assignments, which already withhold
    # 'OPENAI_API_KEY=${OPENAI_API_KEY:-v}' whole. Plain assignment redaction
    # can introduce a bracketed marker after a mapping colon (including
    # annotations). Normalize those expressions in this same pass so repeated
    # sanitization does not change the result.
    return _redact_mapping_values(_redact_fallback_defaults(_redact_plain_assignments(text)))


def _opaque_option(option: str) -> bool:
    """An argv option whose last word names a credential ('--key', '--openai-key').

    As on a command line, only a value that looks like an opaque key is one.
    """
    name = option.lstrip("-")
    return not name.lower().startswith(("no-", "no_")) and _credential_name(name, numbered=True)


def _opaque_literal(value: Any) -> bool:
    """A string that looks like an opaque key."""
    return isinstance(value, str) and _credential_literal(value, positional=False)


def _record_has_secret_value(item: Mapping, *, environment: bool = False, extended: bool = False) -> bool:
    """Whether a name/value record's name marks its value as a credential.

    The established rule reads the whole name as a sensitive key. The
    ``extended`` one reads it as a setting (see ``_setting_level``), as the
    text passes read a record: 'OpenAI:Secret' withholds any value, and
    'OpenAIKey' or 'KEY1' a value that looks like an opaque key.
    """
    name = item.get("name") or item.get("Name") or item.get("key") or item.get("Key")
    if not isinstance(name, str):
        return False
    if not extended:
        return _sensitive_assignment_key(name) if environment else _sensitive_name(name)
    level = _setting_level(name, record=not environment)
    return _setting_value_withheld(level, item.get("value") or item.get("Value")) if level else False


def _credential_member(key: str, child: Any, *, group: bool) -> bool:
    """Whether the field ``key`` (lowercase) of a credential container holds credential material.

    A nested record or list does, whatever its name: a provider or name field
    can itself hold a credential record. A scalar does unless it is a
    descriptive label beside the secret ('provider', 'name', 'status'). An
    'id' is one in a container named for credentials ('credentials.id'),
    but names an identity under other credential names ('api_key.id', Azure
    'identity.authorization.objectId'), and a copied short ID must not taint
    otherwise independent caller labels or report identities.
    """
    if isinstance(child, (Mapping, list, tuple)):
        return True
    return key not in _CREDENTIAL_DESCRIPTORS or (group and key in _CREDENTIAL_GROUP_IDS)


class _Sanitizer:
    """One ``sanitize`` pass: the credential values it knows and its work budgets.

    ``discover`` collects the values of sensitive fields, secret-shaped
    records, credential options and (optionally) environment blocks;
    ``order`` ranks them for replacement; ``clean`` copies the input,
    withholding them from every other field as well. The established pass
    uses the established rules and text passes; the ``extended`` one, run
    on the established pass's copy, the rules added since (see ``sanitize``),
    and knows only the values those find.
    """

    def __init__(self, *, redact_short_secrets: bool, env_values_are_secrets: bool, extended: bool) -> None:
        self.redact_short_secrets = redact_short_secrets
        self.env_values_are_secrets = env_values_are_secrets
        self.extended = extended
        self.known: set[str] = set()
        # The same aliased object can occur both outside and inside an environment
        # block. Revisit it under the stricter naming policy, but still bound cycles.
        self.discovered: set[tuple[int, bool, bool]] = set()
        self.ordered: list[str] = []
        self.work = 0
        self.cleaning: set[int] = set()
        self.cleaning_steps = 0

    def charge(self, amount: int) -> None:
        self.work += amount
        if self.work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("credential replacement work limit exceeded")

    def remember(self, child: Any) -> None:
        child = _plain(child)
        if isinstance(child, str) and child:
            if child != REDACTED and not _FINGERPRINT.fullmatch(child):
                self.known.add(child)
                # Library diagnostics often use repr(), which escapes secret
                # control characters. Remove both spellings in sibling fields.
                escaped = repr(child)[1:-1]
                if escaped != child:
                    self.known.add(escaped)

    def discover(self, item: Any, depth: int = 0, *, environment: bool = False, auth: bool = False) -> None:
        """``auth``: the item lies under an auth container, whose generic credential fields
        ``clean`` withholds whatever their shape; an opaque value there is learned so a copy
        in a sibling field goes too (the nested pass learns the leaves of a record or list)."""
        item = _plain(item)
        identity = (id(item), environment, auth)
        if depth > 64 or (isinstance(item, _CONTAINERS) and identity in self.discovered):
            return
        if isinstance(item, _CONTAINERS):
            self.discovered.add(identity)
        # The extended pass knows only the values the added rules find: the
        # established pass already withheld and removed the others.
        established = not self.extended
        if isinstance(item, Mapping):
            if _record_has_secret_value(item, environment=environment, extended=self.extended):
                self.remember(item.get("value") or item.get("Value"))
            for key, child in item.items():
                name = str(key)
                if established and (_sensitive_key(name) or environment and _sensitive_assignment_key(name)):
                    self.remember(child)
                if established and auth and name.lower() in _AUTH_VALUE_KEYS:
                    # Only an opaque value: the same fields hold labels and placements
                    # ('header', 'in') that must not withhold every field they occur in.
                    if isinstance(child, (list, tuple, set, frozenset)):
                        for member in child:
                            if _opaque_literal(member):
                                self.remember(member)
                    elif _opaque_literal(child):
                        self.remember(child)
                child_auth = auth or name.lower() in _AUTH_CONTAINER_KEYS
                child_environment = environment or name.lower() in _ENVIRONMENT_KEYS
                if established and self.env_values_are_secrets and child_environment:
                    if isinstance(child, Mapping):
                        for env_value in child.values():
                            self.remember(env_value)
                    elif isinstance(child, list):
                        for entry in child:
                            if isinstance(entry, Mapping):
                                self.remember(entry.get("value") or entry.get("Value"))
                self.discover(child, depth + 1, environment=child_environment, auth=child_auth)
        elif isinstance(item, (set, frozenset)):
            for child in item:
                self.discover(child, depth + 1, environment=environment, auth=auth)
        elif isinstance(item, (list, tuple)):
            if self.extended:
                for index in _aws_configure_argv_secret_indices(item):
                    self.remember(item[index])
            previous: Any = None
            for child in item:
                # An argv option or value given as bytes is read as its text; the
                # established pass remembers only text otherwise, and a credential
                # after a bytes option was shown in a sibling field.
                option = _plain(previous) if isinstance(previous, (bytes, bytearray)) else previous
                value = _plain(child) if isinstance(child, (bytes, bytearray)) else child
                if isinstance(option, str) and option.startswith("-") and "=" not in option:
                    if (established and _sensitive_flag(option.lstrip("-"))) or (
                        self.extended and _opaque_option(option) and _opaque_literal(value)
                    ):
                        self.remember(child)
                elif established and isinstance(value, str) and value.startswith("-") and "=" in value:
                    # --api-key=VALUE: the value is a credential to remove from
                    # sibling fields, exactly as for a separate argv entry.
                    flag, _, flag_value = value.partition("=")
                    if _sensitive_flag(flag.lstrip("-")):
                        self.remember(flag_value)
                self.discover(child, depth + 1, environment=environment, auth=auth)
                previous = child

    def text_passes(self, text: str) -> str:
        """This pass's text passes: the established ones, or the extended ones on their result.

        Only the established passes check the text's size, as before. The
        extended ones read what the established passes made of a value within
        the limit, which markers can make longer than the limit ('pwd=ab'
        becomes 'pwd=[REDACTED]'), as ``sanitize_text`` does.
        """
        return _redact_extended(text) if self.extended else _sanitize_established(text)

    def order(self) -> None:
        """Rank the known values longest first for replacement."""
        if self.redact_short_secrets:
            # The structural pass can rewrite part of a whole configured secret.
            # Remember that spelling too so its other opaque fragments are removed.
            for value in tuple(self.known):
                self.charge(len(value))
                spelling = self.text_passes(value)
                if spelling and spelling != REDACTED:
                    self.known.add(spelling)
        self.ordered = sorted(self.known, key=len, reverse=True)

    def text(self, item: str) -> str:
        # The extended pass is charged only for removing the values it knows,
        # which the established pass did not know. Its text passes are linear,
        # as in sanitize_text, so a value in which it finds none cannot reach
        # a limit the established pass did not.
        self.charge(len(item) * (len(self.ordered) + (0 if self.extended else 1)))
        if self.redact_short_secrets and self.ordered:
            # Preserve recognizable token/URL structure before a short known
            # secret changes a scheme, hostname, or credential prefix. For
            # example, removing 'hooks' first would hide a Slack webhook URL
            # from the path-secret rules while retaining its capability token.
            self.charge(len(item))
            item = self.text_passes(item)
        for value in self.ordered:
            if self.redact_short_secrets:
                item = self.replace(item, value)
            elif len(value) < 8 and value in item:
                # Default report sanitization withholds the entire field for
                # short secrets; this avoids both expansion and partial leaks.
                return REDACTED
            else:
                # Keep line counts stable: excerpts index sanitized text by the
                # raw line number, and a multi-line secret would shift them.
                item = item.replace(value, REDACTED + "\n" * value.count("\n"))
        return self.text_passes(item)

    def replace(self, item: str, secret: str) -> str:
        """Replace each occurrence of a known ``secret`` in ``item`` within the size limit."""
        self.charge(3 * len(item))
        # A one-character secret must not recursively expand markers
        # inserted by a previous replacement (e.g. a password of 'R').
        # Only protect markers when the secret occurs inside one: a
        # longer real secret may itself contain the literal marker.
        parts = item.split(REDACTED) if secret in REDACTED else [item]
        occurrences = sum(part.count(secret) for part in parts)
        projected_chars = len(item) + occurrences * max(0, len(REDACTED) - len(secret))
        # The extended pass reads the established pass's text, which markers
        # can already have made longer than the limit. A replacement may not
        # grow a text past the limit, nor grow a text already past it.
        limit = max(_MAX_SANITIZATION_CHARS, len(item)) if self.extended else _MAX_SANITIZATION_CHARS
        if projected_chars > limit:
            raise SanitizationLimitError("credential replacement size limit exceeded")
        return REDACTED.join(part.replace(secret, REDACTED) for part in parts)

    def clean(self, item: Any, depth: int = 0, *, auth: bool = False) -> Any:
        """``auth``: the item lies under an ``auth`` container, where a generic ``value``,
        ``key`` or ``credential`` field is a credential at any depth and inside lists."""
        self.cleaning_steps += 1
        if self.cleaning_steps > _MAX_SANITIZATION_NODES:
            raise SanitizationLimitError("sanitization work limit exceeded")
        if depth > 64:
            return REDACTED
        if isinstance(item, _CONTAINERS):
            if id(item) in self.cleaning:
                return REDACTED
            self.cleaning.add(id(item))
        try:
            return self.clean_value(item, depth, auth=auth)
        finally:
            if isinstance(item, _CONTAINERS):
                self.cleaning.discard(id(item))

    def clean_value(self, item: Any, depth: int, *, auth: bool = False) -> Any:
        item = _plain(item)
        if isinstance(item, Mapping):
            return self.clean_mapping(item, depth, auth=auth)
        if isinstance(item, (list, tuple)):
            sequence_out: list[Any] = []
            redact_next = opaque_next = False
            for child in item:
                if redact_next or (opaque_next and _opaque_literal(child)):
                    sequence_out.append(_redact_value(child))
                    redact_next = opaque_next = False
                else:
                    sequence_out.append(self.clean(child, depth + 1, auth=auth))
                    opaque_next = False
                    if isinstance(child, str) and child.startswith("-") and "=" not in child:
                        redact_next = _sensitive_flag(child.lstrip("-"))
                        opaque_next = self.extended and _opaque_option(child)
            return tuple(sequence_out) if isinstance(item, tuple) else sequence_out
        if isinstance(item, (set, frozenset)):
            members = [self.clean(child, depth + 1) for child in item]
            return frozenset(members) if isinstance(item, frozenset) else set(members)
        if isinstance(item, (bytes, bytearray)):
            # Decode tolerantly: json default=str would otherwise print the raw
            # bytes. Untouched content keeps its exact bytes.
            decoded = bytes(item).decode("utf-8", errors="replace")
            cleaned = self.text(decoded)
            if cleaned == decoded:
                return item
            return bytearray(cleaned.encode()) if isinstance(item, bytearray) else cleaned.encode()
        if isinstance(item, str):
            return self.text(item)
        return item

    def clean_mapping(self, item: Mapping, depth: int, *, auth: bool = False) -> dict[str, Any]:
        mapping_out: list[tuple[str, Any]] = []
        for key, child in _all_members(item):
            name = str(key)
            result: Any
            if (
                _sensitive_key(name)
                or (name.lower() == "value" and _record_has_secret_value(item, extended=self.extended))
                # Under an auth block a generic 'value', 'key' or 'credential' field is
                # credential material whatever its shape, as a sensitive key's value is.
                or (auth and name.lower() in _AUTH_VALUE_KEYS)
            ):
                result = _redact_value(child)
            elif name.lower() in _ENVIRONMENT_KEYS and isinstance(child, Mapping):
                members = [(self.text(str(k)), _redact_value(v)) for k, v in _all_members(child)]
                result = _copied(child, members)
            elif name.lower() in _ENVIRONMENT_KEYS and isinstance(child, list):
                result = [self.clean_environment_entry(entry, depth) for entry in child]
            elif (auth or name.lower() in _AUTH_CONTAINER_KEYS) and isinstance(child, (Mapping, list, tuple)):
                # An auth block's credential fields can sit in a nested scheme record
                # ('auth.basic.value') or in a list of them; the rule follows the block down.
                # Every member keeps the mapping rules above and the environment rules
                # before this one: a sensitive key holds a credential whatever its type.
                result = self.clean(child, depth + 1, auth=True)
            else:
                result = self.clean(child, depth + 1)
            mapping_out.append((self.text(name), result))
        return _copied(item, mapping_out)

    def clean_environment_entry(self, entry: Any, depth: int) -> Any:
        """One entry of an environment list: a record's value is withheld whatever its name."""
        if not isinstance(entry, Mapping):
            return _redact_value(entry)
        members = [
            (self.text(str(k)), _redact_value(v) if str(k).lower() == "value" else self.clean(v, depth + 1))
            for k, v in _all_members(entry)
        ]
        return _copied(entry, members)


class _NestedSanitizer(_Sanitizer):
    """The last ``sanitize`` pass: the scalar leaves nested in a container ``clean`` withholds whole.

    The value of a sensitive key or of a secret-named record can be a record
    or a list. Its leaves are credential material as well (see
    ``_credential_member``), so a copy in an unrelated field must not survive
    because the credential is nested. Those leaves also hold what the other
    passes read to withhold a credential beside them: an option name
    ('--webhook_secret'), a setting or record name ('PASSWORD_1'), a tag or a
    command word. Removed before those passes, such a leaf hid that context
    and the credential behind it was kept. This pass therefore runs last and
    adds no text rule: ``discover`` reads the input for the leaves, and
    ``clean`` removes them, with the spelling the text passes give them, from
    the copy the extended pass left, where they can only add markers. It is
    charged and bounded as the extended pass, which also reads a copy.
    """

    def __init__(self, *, redact_short_secrets: bool) -> None:
        super().__init__(
            redact_short_secrets=redact_short_secrets, env_values_are_secrets=False, extended=True
        )
        # An aliased object can occur both outside and inside a credential
        # container. Revisit it under the stricter parent, but still bound cycles.
        self.containers: set[tuple[int, bool, bool, bool, bool, bool]] = set()

    def discover(
        self,
        item: Any,
        depth: int = 0,
        *,
        environment: bool = False,
        credential: bool = False,
        credential_group: bool = False,
        auth: bool = False,
        opaque_only: bool = False,
    ) -> None:
        """Remember the leaves of the credential containers in ``item``.

        ``credential`` marks a container that ``clean`` withholds whole: the
        value of a sensitive key, of a record named for a secret by the
        established or the added rules, or a member of such a container.
        ``credential_group`` marks a container named for credentials.
        ``auth`` marks an item under an auth block, whose generic ``value``,
        ``key`` and ``credential`` fields ``clean`` withholds whatever their
        shape. Such a field, and every leaf nested in it (``opaque_only``), is
        remembered only when it looks like an opaque key: the same fields hold
        labels, placements and URLs ('header', 'in', a Postman token request's
        'resource' record) that must not withhold every field or key they occur in.
        """
        item = _plain(item)
        identity = (id(item), environment, credential, credential_group, auth, opaque_only)
        if depth > 64 or (isinstance(item, _CONTAINERS) and identity in self.containers):
            return
        if isinstance(item, _CONTAINERS):
            self.containers.add(identity)
        if isinstance(item, Mapping):
            named_secret = _record_has_secret_value(item, environment=environment) or (
                _record_has_secret_value(item, environment=environment, extended=True)
            )
            for key, child in item.items():
                name = str(key)
                lower_name = name.lower()
                key_sensitive = _sensitive_key(name) or environment and _sensitive_assignment_key(name)
                # 'credentials.id' can itself be opaque secret material;
                # 'api_key.id' names an identity (see _credential_member).
                child_group = credential_group or (
                    key_sensitive
                    and _KEY_NORMALISE.sub("", lower_name).endswith(("credential", "credentials"))
                )
                # A record's value under any casing ('VALUE'), which clean
                # withholds, and the members of a credential container.
                member = (named_secret and lower_name == "value") or (
                    credential and _credential_member(lower_name, child, group=child_group)
                )
                auth_value = auth and lower_name in _AUTH_VALUE_KEYS
                if member or ((auth_value or opaque_only) and _opaque_literal(child)):
                    self.remember(child)
                child_auth = (auth or lower_name in _AUTH_CONTAINER_KEYS) and isinstance(
                    child, (Mapping, list, tuple)
                )
                self.discover(
                    child,
                    depth + 1,
                    environment=environment or lower_name in _ENVIRONMENT_KEYS,
                    credential=key_sensitive or member,
                    credential_group=child_group,
                    auth=child_auth,
                    opaque_only=opaque_only or (auth_value and isinstance(child, _CONTAINERS)),
                )
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                if credential or (opaque_only and _opaque_literal(child)):
                    self.remember(child)
                self.discover(
                    child,
                    depth + 1,
                    environment=environment,
                    credential=credential,
                    credential_group=credential_group,
                    auth=auth,
                    opaque_only=opaque_only,
                )

    def order(self) -> None:
        """Rank the known values, and the spellings the text passes give them, longest first.

        The copy this pass reads went through every text pass, which can have
        withheld part of a known value ('prefix sk-proj-... suffix'). Remove
        that spelling too, so the value's other fragments are not kept.
        """
        for value in tuple(self.known):
            self.charge(len(value))
            spelling = _redact_extended(_sanitize_established(value))
            if spelling and spelling != REDACTED:
                self.known.add(spelling)
        self.ordered = sorted(self.known, key=len, reverse=True)

    def text(self, item: str) -> str:
        """``item`` without the known values; no text pass runs again.

        The markers the earlier passes left are not searched: a value found
        only inside one ('ACT') does not occur in the field.
        """
        self.charge(len(item) * len(self.ordered))
        for value in self.ordered:
            if self.redact_short_secrets:
                item = self.replace(item, value)
                continue
            parts = item.split(REDACTED) if value in REDACTED else [item]
            if len(value) < 8 and any(value in part for part in parts):
                return REDACTED
            # Keep line counts stable, as _Sanitizer.text does.
            marker = REDACTED + "\n" * value.count("\n")
            item = REDACTED.join(part.replace(value, marker) for part in parts)
        return item


def sanitize(value: Any, *, redact_short_secrets: bool = False, env_values_are_secrets: bool = True) -> Any:
    """Return a sanitized JSON-like copy, preserving nonsecret fields and types.

    Environment variable values are omitted regardless of name. Lists additionally
    recognize argv pairs, so ``["--token", "opaque-value"]`` is safe to retain.
    Known credential values are also removed from other fields in the same object.
    Short credentials withhold a matching field by default. Diagnostics can opt
    into bounded substring replacement to retain surrounding diagnostic context.

    ``env_values_are_secrets`` controls whether every environment value is also
    treated as a credential to remove from *sibling* fields. That is right for
    tool and agent configuration, where an ``env`` block is where tokens live and
    a source excerpt can repeat them. A provider inventory record's environment
    holds mostly ordinary settings (``STAGE=prod``, ``WORKERS=4``, a region), and
    removing those from sibling fields destroys resource identities. Producers of
    such records pass ``False``; values under sensitive names, secret-record
    shapes and recognizable credential formats are still removed everywhere.

    Two passes run, as in ``sanitize_text``: the established rules copy the
    value, then the rules added since (settings in name/value records,
    opaque values of argv options named for a credential) copy that copy,
    so they only withhold more than the established pass does. The limits
    apply to the established pass as before. The second pass reads text the
    first one produced, which markers can make longer than the size limit,
    so it checks neither that text nor its length; it is charged only for
    removing the values the added rules find from the other fields, and only
    that removal can reach a limit the established pass did not.

    A third pass then removes the leaves nested in a withheld credential
    container from every other field of that copy (see ``_NestedSanitizer``).
    It runs last, so it too only adds markers: a leaf can be an option or
    setting name the first two passes read to withhold the value after it.
    The values the established pass knew are already removed everywhere.

    The runs glued after a scheme credential's marker are withheld after
    all three, from every field and key, as ``sanitize_text`` withholds them
    after its passes (see ``_withhold_scheme_tails``): withheld earlier, a run
    could take with it the start of a known value ('Bearer token v=x y' for a
    known 'x y'), and the third pass no longer found the rest.

    As ``sanitize_text`` does, a value whose texts hold such a run is read
    twice, so and as the established rules read it, each reading again until
    it settles, and each text of the copy shows only what both readings show
    (see ``_merge_copies``). A value where no credential stops at such a run
    keeps the established rules' copy, as ``sanitize_text`` keeps their
    reading, unless removing the runs that start later lines lets the
    passes withhold more or a run holds a value; a marker then shows where
    each run was (see ``_marked_copy``).

    A container stays a container of its type: the two readings of a
    mapping pair up member by member even where two of its keys read alike
    in one reading and not in the other (see ``_Copy``). A key two members
    share keeps one value, as a dict does.
    """
    _check_sanitization_structure(value)
    reading = _SchemeReading(established=False)
    first = _in_reading(
        reading, lambda: _sanitize_reading(value, redact_short_secrets, env_values_are_secrets)
    )
    shown = _in_reading(reading, lambda: _without_scheme_tails(first))
    if not reading.glued:
        if shown == _without_scheme_tails(first, _without_later_line_runs):
            return _dicts(first)
        return _marked_copy(first, shown)
    plain = _settled(
        shown,
        lambda again: _in_reading(
            _SchemeReading(established=False),
            lambda: _without_scheme_tails(
                _sanitize_reading(again, redact_short_secrets, env_values_are_secrets)
            ),
        ),
    )
    established = _in_reading(
        _SchemeReading(established=True),
        lambda: _settled(
            _sanitize_reading(value, redact_short_secrets, env_values_are_secrets),
            lambda again: _sanitize_reading(again, redact_short_secrets, env_values_are_secrets),
        ),
    )
    return _dicts(_merge_copies(plain, established))


def _sanitize_reading(value: Any, redact_short_secrets: bool, env_values_are_secrets: bool) -> Any:
    """One reading of ``value`` by the three ``sanitize`` passes (see ``sanitize``)."""
    passes = [
        _Sanitizer(
            redact_short_secrets=redact_short_secrets,
            env_values_are_secrets=env_values_are_secrets,
            extended=extended,
        )
        for extended in (False, True)
    ]
    copy = value
    for sanitizer in passes:
        sanitizer.discover(copy)
        sanitizer.order()
        copy = sanitizer.clean(copy)
    nested = _NestedSanitizer(redact_short_secrets=redact_short_secrets)
    nested.discover(value)
    nested.known -= passes[0].known
    if not nested.known:
        return copy
    nested.order()
    return nested.clean(copy)


def _merge_copies(first: Any, second: Any) -> Any:
    """Two readings of one value merged, each text as withheld as both withhold it (see ``_merge_readings``).

    Both copies come from the same value through the same structural rules,
    so they pair up member by member: a mapping by the members of its source
    (see ``_merge_mappings``), a list or tuple by position. A container stays
    a container of its type; only where one reading withholds a value whole
    (as a sensitive key's) is it withheld. Containers that do not pair up
    cannot come from one value, and fail closed.
    """
    if first == second:
        return first
    if isinstance(first, str) and isinstance(second, str):
        return _merge_readings(first, second)
    if isinstance(first, Mapping) and isinstance(second, Mapping):
        return _merge_mappings(first, second)
    if isinstance(first, (list, tuple)) and type(first) is type(second):
        if len(first) != len(second):
            raise SanitizationLimitError("sanitization readings of one value do not pair up")
        members = [_merge_copies(one, other) for one, other in zip(first, second, strict=True)]
        return tuple(members) if isinstance(first, tuple) else members
    if type(first) is type(second) and not isinstance(first, _CONTAINERS):
        # A leaf no text pass reads, the same in both readings ('nan' is not equal to itself).
        return first
    return REDACTED


def _merge_mappings(first: Mapping, second: Mapping) -> dict[str, Any]:
    """Two readings of one mapping, merged member by member (see ``_merge_copies``).

    Each reading holds a copy of every member of the source mapping, in its
    order (see ``_Copy``), so the members pair up by their place in it,
    whatever their keys read in either. The result holds the members that
    both readings keep as dicts where keys read alike, in the order of the
    established reading (``second``), which keeps them as the established
    rules did: it shows no member either dropped. A key two of them share
    once merged keeps the later one's value, as a dict built from them does.
    """
    one, other = _all_members(first), _all_members(second)
    if len(one) != len(other):
        raise SanitizationLimitError("sanitization readings of one value do not pair up")
    kept = set(first.view) if isinstance(first, _Copy) else range(len(one))
    merged: dict[str, Any] = {}
    for index in second.view if isinstance(second, _Copy) else range(len(other)):
        if index in kept:
            (key, child), (other_key, other_child) = one[index], other[index]
            merged[_merge_copies(key, other_key)] = _merge_copies(child, other_child)
    return merged


def _without_scheme_tails(item: Any, without: Callable[[str], str] = _without_glued_runs) -> Any:
    """``item``, a copy ``sanitize`` made, with ``without`` applied to each text and key.

    ``without`` is ``_without_glued_runs`` unless ``sanitize`` compares the
    copy (see ``_without_later_line_runs``).

    The copy holds only what ``clean`` returns: new mappings with text keys,
    lists and tuples, nested no deeper than ``clean`` goes, and texts and
    other leaves it keeps as they are (``_plain`` has turned bytes into text
    and sets into lists). A mapping keeps every member, also where two keys
    read alike once their runs go (see ``_Copy``).
    """
    if isinstance(item, str):
        return without(item)
    if isinstance(item, Mapping):
        return _copied(
            item,
            [
                (_without_scheme_tails(key, without), _without_scheme_tails(child, without))
                for key, child in _all_members(item)
            ],
        )
    if isinstance(item, (list, tuple)):
        members = [_without_scheme_tails(child, without) for child in item]
        return tuple(members) if isinstance(item, tuple) else members
    return item


def _check_sanitization_structure(value: Any) -> None:
    """Bound expanded output before copying an alias DAG or running redaction.

    Memoized subtree costs count *every occurrence* in JSON serialization,
    without traversing repeated objects exponentially. Cycles become one
    redaction marker, matching ``sanitize``; excessive depth is an explicit
    incomplete scan, never a silently truncated clean result.
    """
    active: set[int] = set()
    memo: dict[int, tuple[int, int, int]] = {}

    def cost(item: Any) -> tuple[int, int, int]:
        # A set is read as a list of its members (see ``_plain``), and a member
        # can itself be a tuple or a set: each member is costed as a list item.
        if not isinstance(item, _CONTAINERS):
            if isinstance(item, (bytes, bytearray, memoryview)):
                return 1, len(item), 1
            return 1, len(item) if isinstance(item, str) else 0, 1
        identity = id(item)
        if identity in active:
            return 1, len(REDACTED), 1
        if identity in memo:
            return memo[identity]
        if len(active) >= 64:
            raise SanitizationLimitError("sanitization nesting limit exceeded")
        active.add(identity)
        nodes, chars, height = 1, 0, 1
        children = item.items() if isinstance(item, Mapping) else ((None, child) for child in item)
        for key, child in children:
            child_nodes, child_chars, child_height = cost(child)
            nodes += child_nodes + (key is not None)
            chars += child_chars + (len(str(key)) if key is not None else 0)
            height = max(height, child_height + 1)
            if nodes > _MAX_SANITIZATION_NODES or chars > _MAX_SANITIZATION_CHARS:
                raise SanitizationLimitError("sanitization expanded output limit exceeded")
            if height > 64:
                raise SanitizationLimitError("sanitization nesting limit exceeded")
        active.remove(identity)
        memo[identity] = (nodes, chars, height)
        return memo[identity]

    nodes, chars, _ = cost(value)
    if nodes > _MAX_SANITIZATION_NODES or chars > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("sanitization expanded output limit exceeded")


def policy_token() -> tuple[Any, ...]:
    """Identify the redaction rules and limits currently in force.

    State verified clean by one policy is not clean under another. Callers
    that cache a verified-clean digest key it by this value, so a rule set
    replaced at runtime (for example a patched sensitive-name list or a
    lowered limit) is applied on their next pass instead of being skipped.
    The tuple holds the live policy objects, which makes an unchanged policy
    compare by identity; mutable collections are snapshotted by value. Every
    binding in every redaction module counts, including the names one imports
    from another, so a rule replaced in any single module changes the token.
    """
    return tuple(_policy_value(namespace[name]) for namespace, name in _POLICY_BINDINGS)


def _policy_value(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return frozenset(value)
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, dict):
        return tuple(value.items())
    return value


class _RedactionNamespace(types.ModuleType):
    """This module's type: the redaction modules read and written as one namespace.

    A name that one of them binds reads through this module, and writing a
    name here writes it in every module that binds it, so every pass sees the
    replacement, as when they all lived in this module. A name deleted here
    is deleted from each of them, and returns to each when set again. Classes
    are shared objects, so a patched method reaches every pass without this.
    """

    # The modules this one drives. Each name is defined in exactly one of them.
    # (Class attributes: module objects are no rule, and the policy token of a
    # finding is copied with it.)
    _modules: tuple[types.ModuleType, ...] = (
        redaction_rules,
        redaction_formats,
        redaction_statements,
        redaction_assignments,
        redaction_calls,
        redaction_commands,
        redaction_markup,
        redaction_entropy,
    )
    # The modules, this one included, that bind each name once all are loaded.
    _binders: dict[str, tuple[types.ModuleType, ...]] = {}

    def __getattr__(self, name: str) -> Any:
        for module in self._binders.get(name, ()):
            namespace = vars(module)
            if name in namespace:
                return namespace[name]
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        for module in self._binders.get(name, (self,)):
            if module is self:
                super().__setattr__(name, value)
            else:
                setattr(module, name, value)

    def __delattr__(self, name: str) -> None:
        binders = [module for module in self._binders.get(name, (self,)) if name in vars(module)]
        if not binders:
            raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")
        for module in binders:
            if module is self:
                super().__delattr__(name)
            else:
                delattr(module, name)


def _is_policy(value: Any) -> bool:
    """Rules, patterns and limits, plus the helpers the redaction modules define."""
    if isinstance(value, (str, int, float, tuple, list, dict, set, frozenset, re.Pattern)):
        return True
    return isinstance(value, types.FunctionType) and value.__module__ in _POLICY_MODULES


def _binding_modules() -> dict[str, tuple[types.ModuleType, ...]]:
    """The modules, this one included, that bind each name."""
    modules = (sys.modules[__name__], *_RedactionNamespace._modules)
    names = {name for module in modules for name in vars(module) if not name.startswith("__")}
    return {name: tuple(module for module in modules if name in vars(module)) for name in names}


_POLICY_MODULES = frozenset({__name__, *(module.__name__ for module in _RedactionNamespace._modules)})
# Every module-level rule, pattern, limit and helper that this module or one
# it drives binds, computed once all are bound: a newly added policy constant
# is covered without registration.
_POLICY_BINDINGS: tuple[tuple[dict[str, Any], str], ...] = tuple(
    (vars(module), name)
    for module in (sys.modules[__name__], *_RedactionNamespace._modules)
    for name, value in sorted(vars(module).items())
    if not name.startswith("__") and _is_policy(value)
)


_RedactionNamespace._binders = _binding_modules()
# From here on, setting or deleting a name on this module writes every module
# that binds it. Patch rules through shadowscan.utils.redaction only: a name
# set on a redaction_* module directly changes that module alone, and the
# other passes keep the object they imported, so a patched rule or limit would
# apply to some passes and silently not to others.
sys.modules[__name__].__class__ = _RedactionNamespace
