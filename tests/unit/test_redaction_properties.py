"""Property-based tests for the redaction module using Hypothesis.

These tests verify invariants that must hold for *any* input, not just
hand-picked examples: idempotency, credential removal, and crash-freedom
on adversarial unicode.
"""

from __future__ import annotations

import re
import string
from collections.abc import Callable

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.utils import redaction  # noqa: E402
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text  # noqa: E402

# Characters that commonly appear in credentials and source code.
_CREDENTIAL_ALPHABET = string.ascii_letters + string.digits + "/-_=+.@#$%^&*(){}[]|\\:;\"'<>,?! \t\n"

# Well-known credential patterns that sanitize_text must always redact.
_SAMPLE_TOKENS = [
    "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
    "AKIA1234567890ABCDEF",
    "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab1234",
]


@given(text=st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=2000))
@settings(max_examples=200, deadline=5000)
def test_sanitize_text_never_crashes(text: str) -> None:
    """sanitize_text must not raise on arbitrary text within size limits."""
    result = sanitize_text(text)
    assert isinstance(result, str)


@given(text=st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=2000))
@settings(max_examples=200, deadline=5000)
def test_sanitize_text_idempotent(text: str) -> None:
    """Applying sanitize_text twice must produce the same result as once."""
    once = sanitize_text(text)
    twice = sanitize_text(once)
    assert once == twice


@given(text=st.text(max_size=2000))
@settings(max_examples=100, deadline=5000)
def test_sanitize_text_unicode_safety(text: str) -> None:
    """sanitize_text must handle arbitrary unicode without crashing."""
    result = sanitize_text(text)
    assert isinstance(result, str)


# A token starts and ends at an ASCII word boundary: glued to a letter, digit
# or underscore it is part of an identifier ('task-proj-…') or of a longer
# value that is not this token ('AKIA…F0' is not a 20-character key id).
_NOT_A_WORD_END = re.compile(r"(?<![A-Za-z0-9_])\Z")
_NOT_A_WORD_START = re.compile(r"\A(?![A-Za-z0-9_])")


@given(
    token=st.sampled_from(_SAMPLE_TOKENS),
    prefix=st.text(max_size=50).filter(_NOT_A_WORD_END.search),
    suffix=st.text(max_size=50).filter(_NOT_A_WORD_START.search),
)
@settings(max_examples=100, deadline=5000)
def test_known_tokens_always_redacted(token: str, prefix: str, suffix: str) -> None:
    """Known credential patterns must be redacted whatever precedes or follows them."""
    text = prefix + token + suffix
    result = sanitize_text(text)
    assert token not in result


@given(
    data=st.recursive(
        st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=200) | st.integers() | st.none() | st.booleans(),
        lambda children: (
            st.lists(children, max_size=5)
            | st.dictionaries(
                st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
                children,
                max_size=5,
            )
        ),
        max_leaves=20,
    )
)
@settings(max_examples=100, deadline=10000)
def test_sanitize_structured_data_never_crashes(data: object) -> None:
    """sanitize() on nested dicts/lists/scalars must not crash."""
    result = sanitize(data)
    assert result is not None or data is None


@given(safe=st.text(alphabet=string.ascii_lowercase + string.digits + " .,\n", max_size=500))
@settings(max_examples=200, deadline=5000)
def test_safe_text_passes_through(safe: str) -> None:
    """Text without credential patterns should pass through mostly unchanged."""
    result = sanitize_text(safe)
    assert REDACTED not in result or REDACTED in safe


# Texts around a scheme credential: glued runs, runs that start later lines,
# separators and names before planted values. Every value is synthetic.
_PLAIN_VALUE = "hunter2pass"
_OPAQUE_VALUE = "Hv7" + "Qx2Lm9Pw4Rt6Yu1"
_SCHEME_CREDENTIAL = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5"
_SCHEME_PARTS = [
    *(f"{scheme} {_SCHEME_CREDENTIAL}" for scheme in ("Bearer", "Basic", "SSWS")),
    f"Bearer token {_SCHEME_CREDENTIAL}",
    f"Bearer\n{_SCHEME_CREDENTIAL}",
    "Basic dXNlcjpwYXNz==",
    "SSWS abc123",
]
_FOLLOWING_PARTS = [
    *("--x9", "=x9", "--password", "=password", "--auth", "--token", "--a=:", "=v1=", "--cookie"),
    *("--insecure", "---", "=Section=", "--r0", "=abc.def", "--x=abc.def"),
    *("\n", "\n", "\n\n", "\r\n", " ", "\\n", "\t", ": ", " = ", "=", "user: u"),
    *(" password: ", "password: ", " = password: ", "Bearer "),
    # A run on the next line before a name that the passes read only once the run goes.
    *("\n=abc.def = password: ", "\n--r0\n"),
    *(_PLAIN_VALUE, _OPAQUE_VALUE),
]
_SCHEME_TEXTS = st.builds(
    lambda lead, scheme, rest: "".join([*lead, scheme, *rest]),
    st.lists(st.sampled_from(_FOLLOWING_PARTS), max_size=3),
    st.sampled_from(_SCHEME_PARTS),
    st.lists(st.sampled_from(_FOLLOWING_PARTS), min_size=1, max_size=10),
)


def _merged_readings(read: Callable[[], str]) -> tuple[str, list[tuple[str, str]]]:
    """The result of ``read()`` and the pairs of readings ``_merge_readings`` merged on the way."""
    merged: list[tuple[str, str]] = []
    merge = redaction._merge_readings
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            redaction,
            "_merge_readings",
            lambda first, second: merged.append((first, second)) or merge(first, second),
        )
        return read(), merged


def _assert_each_line_shows_only_what_both_readings_show(cleaned: str, plain: str, established: str) -> None:
    lines, plain_lines, established_lines = cleaned.split("\n"), plain.split("\n"), established.split("\n")
    assert len(lines) == len(plain_lines)
    if len(plain_lines) != len(established_lines):
        assert cleaned == REDACTED + "\n" * plain.count("\n")
        return
    for line, one, other in zip(lines, plain_lines, established_lines, strict=True):
        # A line of one reading, the plain line with a marker where a run was, or a withheld line.
        assert line in (one, other, REDACTED + one, REDACTED + "\r" * one.endswith("\r"))
        assert redaction._shows_within(one, line) and redaction._shows_within(other, line)


@given(text=_SCHEME_TEXTS)
@settings(max_examples=300, deadline=None)
def test_sanitize_text_shows_nothing_the_established_reading_withholds(text: str) -> None:
    """Each output line is a line of one of the two readings, and shows only what both show.

    The established reading is the text as the established rules read it,
    the scheme pass withholding a glued run with its credential (outside any
    reading, see ``_SchemeReading``). A text with no glued run returns it, or
    what the step that withholds the runs leaves of it, with a marker where
    a run that started a line was.
    """
    cleaned, merged = _merged_readings(lambda: sanitize_text(text))
    established = redaction._redact_extended(redaction._sanitize_established(text))
    if merged:
        ((plain, settled),) = merged
        _assert_each_line_shows_only_what_both_readings_show(cleaned, plain, settled)
    else:
        without = redaction._in_reading(
            redaction._SchemeReading(established=False),
            lambda: redaction._without_glued_runs(established),
        )
        assert cleaned in (established, redaction._marked_later_lines(established, without))
        if cleaned != established:
            for line, unmarked in zip(cleaned.split("\n"), without.split("\n"), strict=True):
                assert line in (unmarked, REDACTED + unmarked)
    for value in (_PLAIN_VALUE, _OPAQUE_VALUE, _SCHEME_CREDENTIAL):
        assert value in established or value not in cleaned


@given(text=_SCHEME_TEXTS, short=st.booleans())
@settings(max_examples=150, deadline=None)
def test_sanitize_shows_nothing_the_established_copy_withholds(text: str, short: bool) -> None:
    """``sanitize`` keeps the same invariant for each text of the copy (see ``_merge_copies``)."""
    cleaned, merged = _merged_readings(lambda: sanitize({"note": text}, redact_short_secrets=short)["note"])
    established = redaction._sanitize_reading({"note": text}, short, True)["note"]
    if merged:
        ((plain, settled),) = merged
        _assert_each_line_shows_only_what_both_readings_show(cleaned, plain, settled)
    for value in (_PLAIN_VALUE, _OPAQUE_VALUE, _SCHEME_CREDENTIAL):
        assert value in established or value not in cleaned


def _established_rules_settle(text: str, short: bool) -> bool:
    """Whether the established rules, outside any reading, read their own reading of ``text`` alike.

    They do not on every text, at 8fdd67b either: a value after a name
    ('= password: --x9') is withheld or kept with what the line before it
    holds, and only the next sanitization withholds it. Such a text says
    nothing about the step that withholds the runs after a scheme
    credential, which the property below is about.
    """
    once = redaction._redact_extended(redaction._sanitize_established(text))
    if redaction._redact_extended(redaction._sanitize_established(once)) != once:
        return False
    copy = redaction._sanitize_reading({"note": text}, short, True)
    return bool(redaction._sanitize_reading(copy, short, True) == copy)


@given(text=_SCHEME_TEXTS, short=st.booleans())
# Shapes the differential harness found: the run after the glued name went
# only on the second sanitization, and the value after the fourth run of a
# chain was read only then.
@example(text=f"Basic {_SCHEME_CREDENTIAL}--auth\n--r0\n=password=v1=: ---", short=False)
@example(text=f"Bearer {_SCHEME_CREDENTIAL}--token\n=abc.def = password: {_PLAIN_VALUE}", short=True)
@example(
    text=f"Basic {_SCHEME_CREDENTIAL}\n\n\n--r0\n\n\n=x9\n---\n\n\n=abc.def = password: --x9", short=False
)
@settings(max_examples=300, deadline=None)
def test_sanitize_text_and_sanitize_are_idempotent_on_the_scheme_corpus(text: str, short: bool) -> None:
    """Evidence is sanitized more than once: a second sanitization changes nothing.

    A run that starts the line after a name glued to a scheme credential
    ('<token>--token\\n=abc.def = password: v') was examined only on the
    next sanitization, which then withheld the value; so was each run of a
    chain past the readings the step makes. Texts the established rules
    themselves read differently the second time are left out (see
    ``_established_rules_settle``).
    """
    assume(_established_rules_settle(text, short))
    cleaned = sanitize_text(text)
    assert sanitize_text(cleaned) == cleaned
    note = sanitize({"note": text}, redact_short_secrets=short)["note"]
    assert sanitize({"note": note}, redact_short_secrets=short)["note"] == note
