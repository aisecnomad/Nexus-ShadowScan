"""Fuzz targets for the redaction and source-lexing code.

Each target is a function of the bytes a fuzzer produces. It decodes them into one case, runs a
public API on it and raises :class:`InvariantViolation` when a guarantee of that API fails. The
Atheris entry point (``python -m tools.fuzz``) runs the targets under libFuzzer, and
``tests/unit/test_fuzz_targets.py`` runs the same functions from Hypothesis and from the seed
corpus, so the invariants are also checked by the ordinary suite and a harness cannot rot unnoticed.

What a target lets through is part of its contract. The code under test answers hostile input with
its own documented errors: ``SanitizationLimitError`` from the redactor and ``MatchTimeoutError``
from the lexer. Those are the fail-closed outcome, not findings. Every other exception that escapes
is one: a scan must end in a report or in a recorded coverage gap, never in an arbitrary exception.

Every credential here is synthetic and assembled from parts, so no credential-shaped literal is
stored in the repository. A violation message names the invariant and the input's digest and never
quotes the input.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeVar

from shadowscan.connectors.code.source_ranges import noncode_ranges, nul_reading_ranges
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, MatchTimeoutError, language_for_path
from shadowscan.utils.redaction import SanitizationLimitError, sanitize, sanitize_text

_T = TypeVar("_T")

# libFuzzer is asked for inputs up to this long (docs/operations/fuzzing.md), and the Hypothesis
# tests draw the same range, so one input is the same size of text under either driver.
MAX_INPUT_BYTES: Final = 8192


class InvariantViolation(AssertionError):
    """A guarantee of the code under test failed on this input."""


def _violation(data: bytes, message: str) -> InvariantViolation:
    digest = hashlib.sha256(data).hexdigest()[:16]
    return InvariantViolation(f"{message} (input sha256 {digest}..., {len(data)} bytes)")


class Cursor:
    """Reads a fuzz input as a series of decisions followed by text.

    Past the end of the input every read is zero or empty, so a short input is still a case. Bytes
    that are not UTF-8 decode to U+FFFD, as they do when the scanner reads a file that is not UTF-8.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    def byte(self) -> int:
        if self._position >= len(self._data):
            return 0
        value = self._data[self._position]
        self._position += 1
        return value

    def choice(self, options: Sequence[_T]) -> _T:
        return options[self.byte() % len(options)]

    def text(self, size: int) -> str:
        """The next ``size`` bytes (fewer at the end of the input) as text."""
        chunk = self._data[self._position : self._position + size]
        self._position += len(chunk)
        return chunk.decode("utf-8", errors="replace")

    def rest(self) -> str:
        """Every unread byte as text."""
        return self.text(len(self._data))


def selector(options: Sequence[_T], option: _T) -> bytes:
    """The byte that makes :meth:`Cursor.choice` pick ``option``; the seeds are built with it."""
    return bytes([options.index(option)])


# --------------------------------------------------------------------------- redaction


@dataclass(frozen=True)
class Plant:
    """A synthetic credential and the part of it that must not survive sanitization.

    ``isolated`` plants are read in the context of their line (an assignment, a header, a URL, a
    JSON member, a key block), so each is planted on a line of its own. The others are credential
    formats, withheld wherever they stand between two non-word characters.
    """

    name: str
    text: str
    secret: str
    isolated: bool = False


_PEM_BODY = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
    + "VJTUt9Us8cKjMzEfYyjiWA4R4M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNb"
)
_JWT_SIGNATURE = "c3ludGhldGljLXNpZ25hdHVyZS12YWx1ZS0xMjM0NTY3ODkw"
_PASSWORD = "Tr0ub4dor" + "Synthetic9x"
_BEARER = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5"

PLANTS: Final[tuple[Plant, ...]] = (
    Plant(
        "github-token",
        "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    ),
    Plant("aws-key-id", "AK" + "IA" + "QWERTYUIOPASDFGH", "QWERTYUIOPASDFGH"),
    Plant("slack-token", "xo" + "xb-" + "1234567890-abcdefghij", "1234567890-abcdefghij"),
    Plant("openai-key", "sk-" + "proj-" + "abcDEF123456ghiJKL789mnoPQR", "abcDEF123456ghiJKL789mnoPQR"),
    Plant(
        "google-key", "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    ),
    Plant(
        "jwt",
        "ey"
        + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + "ey"
        + "JzdWIiOiJzeW50aGV0aWMtdXNlciJ9."
        + _JWT_SIGNATURE,
        _JWT_SIGNATURE,
    ),
    Plant(
        "private-key",
        "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY + "\n-----END PRIVATE KEY-----",
        _PEM_BODY,
        True,
    ),
    Plant("bearer-header", "Authorization: Bearer " + _BEARER, _BEARER, True),
    Plant(
        "basic-header",
        "Authorization: Basic " + "dXNlcjpzeW50aGV0aWMtcGFzcw==",
        "dXNlcjpzeW50aGV0aWMtcGFzcw",
        True,
    ),
    Plant("url-password", "https://svc:" + _PASSWORD + "@host.example/path", _PASSWORD, True),
    Plant("query-key", "https://api.example/v1?api_" + "key=" + _PASSWORD, _PASSWORD, True),
    Plant("assignment", "pass" + 'word = "' + _PASSWORD + '"', _PASSWORD, True),
    Plant("export", "export API_" + "TOKEN=" + _PASSWORD, _PASSWORD, True),
    Plant("json-member", '{"client_' + 'secret": "' + _PASSWORD + '"}', _PASSWORD, True),
)

# What may stand directly before and after a format credential. All are non-word characters:
# glued to a letter, digit or underscore a credential is part of a longer value that is not it.
SEPARATORS: Final = (
    "\n",
    " ",
    "\t",
    '"',
    "'",
    "=",
    ":",
    "(",
    ")",
    ",",
    "/",
    ";",
    "\\n",
    "%3D",
    "\r\n",
    "\x00",
)
_KEYS: Final = ("note", "name", "command", "args", "env", "headers", "url", "id", "value", "config", "data")


def planted_text(plant: Plant, context: str, cut: int, before: str, after: str) -> str:
    """``context`` with ``plant`` inserted at ``cut`` / 255 of its length.

    An isolated plant gets a line to itself whatever the separators say.
    """
    if plant.isolated:
        before = after = "\n"
    point = len(context) * cut // 255
    return context[:point] + before + plant.text + after + context[point:]


def _planted(cursor: Cursor, plant: Plant, size: int | None = None) -> str:
    before, after, cut = cursor.choice(SEPARATORS), cursor.choice(SEPARATORS), cursor.byte()
    context = cursor.rest() if size is None else cursor.text(size)
    return planted_text(plant, context, cut, before, after)


def redaction_text_input(
    plant: Plant, context: str, *, cut: int = 128, before: str = "\n", after: str = "\n"
) -> bytes:
    """The input that makes :func:`check_redaction_text` plant ``plant`` in ``context``."""
    header = selector(PLANTS, plant) + selector(SEPARATORS, before) + selector(SEPARATORS, after)
    return header + bytes([cut]) + context.encode("utf-8")


def check_redaction_text(data: bytes) -> None:
    """``sanitize_text`` withholds a planted credential and keeps the text's line breaks.

    The credential is planted in fuzz-chosen text, which can be anything: code, JSON, a half-open
    quote, an escape sequence. The text comes back with the line breaks it had, or the call raises
    ``SanitizationLimitError``.
    """
    cursor = Cursor(data)
    plant = cursor.choice(PLANTS)
    text = _planted(cursor, plant)
    try:
        cleaned = sanitize_text(text)
    except SanitizationLimitError:
        return
    if not isinstance(cleaned, str):
        raise _violation(data, f"sanitize_text returned a {type(cleaned).__name__}, not a str")
    if plant.secret in cleaned:
        raise _violation(data, f"sanitize_text left the {plant.name} credential in its output")
    if cleaned.count("\n") != text.count("\n"):
        raise _violation(data, "sanitize_text changed the number of line breaks")


def _node(cursor: Cursor, plant: Plant, depth: int) -> Any:
    """A JSON-like value the cursor describes; below a few levels only scalars."""
    kind = cursor.byte() % (8 if depth < 4 else 5)
    if kind == 0:
        return None
    if kind == 1:
        return bool(cursor.byte() & 1)
    if kind == 2:
        return cursor.byte()
    if kind in (3, 4):
        return cursor.text(cursor.byte() % 64)
    if kind == 5:
        return [_node(cursor, plant, depth + 1) for _ in range(cursor.byte() % 4)]
    if kind == 6:
        return {cursor.choice(_KEYS): _node(cursor, plant, depth + 1) for _ in range(cursor.byte() % 4)}
    return _planted(cursor, plant, cursor.byte() % 64)


def encode_node(value: Any) -> bytes:
    """The bytes from which :func:`_node` rebuilds ``value``, a tree of at most three members per level.

    Strings are shorter than 64 bytes and integers below 256; ``None``, booleans, lists and mappings
    keyed by the names in ``_KEYS`` make up the rest. The seeds are built with it, and a test checks
    that it and :func:`_node` stay each other's inverse.
    """
    if value is None:
        return bytes([0])
    if isinstance(value, bool):
        return bytes([1, int(value)])
    if isinstance(value, int):
        return bytes([2, value])
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return bytes([3, len(raw)]) + raw
    if isinstance(value, list):
        return bytes([5, len(value)]) + b"".join(encode_node(item) for item in value)
    return bytes([6, len(value)]) + b"".join(
        selector(_KEYS, key) + encode_node(item) for key, item in value.items()
    )


def encode_planted_leaf(context: str, *, cut: int = 128, before: str = "\n", after: str = "\n") -> bytes:
    """The bytes from which :func:`_node` plants the credential in ``context`` (under 64 bytes)."""
    raw = context.encode("utf-8")
    return (
        bytes([7, len(raw)]) + selector(SEPARATORS, before) + selector(SEPARATORS, after) + bytes([cut]) + raw
    )


def redaction_record_input(
    plant: Plant, payload: bytes, note: str, *, flags: int = 0, cut: int = 128
) -> bytes:
    """The input that makes :func:`check_redaction_record` sanitize a record around ``payload``.

    ``payload`` is the bytes of one tree (see :func:`encode_node`); ``note`` is the text the credential
    is planted in under the ``note`` member.
    """
    separators = selector(SEPARATORS, "\n") * 2
    return (
        selector(PLANTS, plant) + bytes([flags]) + payload + separators + bytes([cut]) + note.encode("utf-8")
    )


def check_redaction_record(data: bytes) -> None:
    """``sanitize`` withholds a planted credential from a JSON-like record and leaves the record alone.

    The record holds the credential under ``note`` and, under ``payload``, a fuzz-shaped tree of
    mappings, lists and scalars that can hold it too. ``sanitize`` returns a copy: it does not change
    what it was given, and the copy is JSON.
    """
    cursor = Cursor(data)
    plant = cursor.choice(PLANTS)
    flags = cursor.byte()
    record = {"payload": _node(cursor, plant, 0), "note": _planted(cursor, plant)}
    before = copy.deepcopy(record)
    try:
        cleaned = sanitize(record, redact_short_secrets=bool(flags & 1), env_values_are_secrets=not flags & 2)
    except SanitizationLimitError:
        return
    if record != before:
        raise _violation(data, "sanitize changed the record it was given")
    try:
        dumped = json.dumps(cleaned)
    except (TypeError, ValueError) as exc:
        raise _violation(data, f"sanitize returned a value that is not JSON ({type(exc).__name__})") from exc
    if plant.secret in dumped:
        raise _violation(data, f"sanitize left the {plant.name} credential in its output")


# --------------------------------------------------------------------------- lexing

# The (language, extension, JSX) triples the filesystem connector passes to the lexer: every source
# extension, read as the language the matcher assigns it, and as JSX where the extension declares it.
LEXERS: Final[tuple[tuple[str | None, str, bool], ...]] = (
    *(
        (language_for_path(f"x{extension}"), extension, extension in {".jsx", ".tsx"})
        for extension in sorted(SOURCE_EXTENSIONS - {".ipynb"})
    ),
    (None, "", False),
)


def _check_spans(data: bytes, spans: object, length: int, reading: str) -> None:
    """``spans`` is a list of ``(start, end)`` integer pairs inside the text, sorted by start."""
    if not isinstance(spans, list):
        raise _violation(data, f"the {reading} spans are a {type(spans).__name__}, not a list")
    previous = 0
    for span in spans:
        if not (isinstance(span, tuple) and len(span) == 2 and all(type(edge) is int for edge in span)):
            raise _violation(data, f"a {reading} span is not a pair of integers")
        start, end = span
        if not 0 <= start <= end <= length:
            raise _violation(data, f"a {reading} span lies outside the text or runs backwards")
        if start < previous:
            raise _violation(data, f"the {reading} spans are not sorted")
        previous = start


def check_lexing(data: bytes) -> None:
    """``noncode_ranges`` and ``nul_reading_ranges`` return in-bounds, sorted, repeatable spans.

    The input picks a language and file extension, and the rest of it is lexed as that source. The
    lexer may stop with ``MatchTimeoutError`` (its look-ahead and match budgets) and with nothing
    else. A source with NUL bytes is also lexed the way the connector reads it: without them, then
    combined with the reading that keeps them.
    """
    cursor = Cursor(data)
    language, extension, jsx = cursor.choice(LEXERS)
    text = cursor.rest()
    try:
        spans, incomplete = noncode_ranges(text, language, extension, jsx=jsx)
        if not isinstance(incomplete, bool):
            raise _violation(data, "noncode_ranges reported incompleteness as a non-bool")
        _check_spans(data, spans, len(text), "ignored")
        if noncode_ranges(text, language, extension, jsx=jsx) != (spans, incomplete):
            raise _violation(data, "noncode_ranges gave two answers for one text")
        if "\x00" in text:
            without = text.replace("\x00", "")
            kept, _ = noncode_ranges(without, language, extension, jsx=jsx)
            combined, _ = nul_reading_ranges(text, kept, language, extension, jsx=jsx)
            _check_spans(data, combined, len(without), "NUL-reading")
    except MatchTimeoutError:
        return


TARGETS: Final[dict[str, Callable[[bytes], None]]] = {
    "redaction-text": check_redaction_text,
    "redaction-record": check_redaction_record,
    "lexing": check_lexing,
}
