"""Generated secrets in snippets are withheld whatever names or calls surround them."""

from __future__ import annotations

import string

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.models import Evidence  # noqa: E402
from shadowscan.utils.redaction import REDACTED  # noqa: E402
from shadowscan.utils.redaction_entropy import (  # noqa: E402
    looks_random,
    withhold_random_literals,
    withhold_random_literals_cut,
)

_BASE62 = string.ascii_letters + string.digits
# Shapes the name- and format-based passes do not recognize: no credential-like
# name, no provider prefix, the literal labelled only by a comment or a call.
_TEMPLATES = [
    'client = Widget("{s}")',
    "Init('{s}')  # our key",
    'cfg.put("blob", "{s}")',
    'opts = {{"x": "{s}"}}',
    "const v = `{s}`;",
    'Configure(settings, "{s}", retries=3)',
    # A token run between two literals must not pair their quotes and hide the second.
    'k = "v1-"+deploymentPrefixName2024+"{s}"',
]


@given(
    secret=st.text(alphabet=_BASE62, min_size=32, max_size=64),
    template=st.sampled_from(_TEMPLATES),
)
@settings(max_examples=300, deadline=5000)
def test_random_looking_literals_never_survive_a_snippet(secret: str, template: str) -> None:
    assume(looks_random(secret))
    snippet = template.format(s=secret)
    cleaned = Evidence(signal="s", description="d", snippet=snippet).snippet
    assert cleaned is not None and secret not in cleaned and REDACTED in cleaned


@given(
    words=st.lists(
        st.sampled_from(["user", "profile", "service", "client", "agent", "model", "config"]), min_size=3
    ),
    digits=st.text(alphabet=string.digits, max_size=2),
    style=st.sampled_from(["snake", "camel", "kebab"]),
)
@settings(max_examples=200, deadline=5000)
def test_ordinary_identifiers_keep_their_text(words: list[str], digits: str, style: str) -> None:
    if style == "snake":
        name = "_".join(words) + digits
    elif style == "kebab":
        name = "-".join(words) + digits
    else:
        name = words[0] + "".join(w.capitalize() for w in words[1:]) + digits
    snippet = f'handler = "{name}"'
    assert withhold_random_literals(snippet) == snippet


@pytest.mark.parametrize(
    "value",
    [
        "3f9a1c2b4d5e6f708192a3b4c5d6e7f801234567",  # git SHA
        "550e8400-e29b-41d4-a716-446655440000",  # UUID
        "gpt-4o-mini-2024-07-18",  # model id
        "AbstractSingletonProxyFactoryBean2",
        "OAuth2ClientCredentialsGrant4",
    ],
)
def test_digests_ids_and_names_are_not_random(value: str) -> None:
    assert not looks_random(value)


def test_the_fallback_is_idempotent_and_applies_when_a_finding_is_sanitized():
    from shadowscan.models import Finding, Kind, Surface

    secret = "Zq8Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="t",
        resource="r",
        resource_type="repo",
    )
    finding.evidence.append(Evidence(signal="s", description="d"))
    finding.evidence[0].snippet = f'Init("{secret}")'  # set after construction, before export
    finding.sanitize()
    assert finding.evidence[0].snippet == f'Init("{REDACTED}")'
    assert withhold_random_literals(finding.evidence[0].snippet) == finding.evidence[0].snippet


_SECRET = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"  # synthetic, built at runtime


@pytest.mark.parametrize("tail", ["\u2026", "", "\nnext = 1"])
def test_a_literal_cut_before_its_closing_quote_is_still_withheld(tail: str) -> None:
    # An excerpt trims long lines and appends an ellipsis, which can cut a literal before its
    # closing quote; what remains still begins with the secret.
    assert looks_random(_SECRET[:24])
    snippet = f'client = Widget("{_SECRET[:24]}{tail}'
    cleaned = withhold_random_literals(snippet)
    assert _SECRET[:24] not in cleaned and REDACTED in cleaned and cleaned.endswith(tail)
    assert withhold_random_literals('handler = "user_profile_service') == 'handler = "user_profile_service'


def test_the_filesystem_excerpt_cannot_leave_a_truncated_literal() -> None:
    from shadowscan.connectors.code.filesystem import _excerpt

    line = "client = Widget(" + ", ".join(f"opt{i}=True" for i in range(11)) + f', "{_SECRET}")'
    snippet = _excerpt([line], 1)
    # The whole line is read before the cut, so the literal is withheld in the excerpt itself.
    assert _SECRET[:6] not in snippet and REDACTED in snippet
    cleaned = Evidence(signal="s", description="d", snippet=snippet).snippet
    assert cleaned is not None and _SECRET[:6] not in cleaned and REDACTED in cleaned


def test_a_literal_the_excerpt_cut_shortens_below_the_minimum_is_withheld() -> None:
    from shadowscan.connectors.code.filesystem import _excerpt

    line = "client = Client(region='eu-west-1', " + "timeout_seconds=30, " * 5 + f'token="{_SECRET}")'
    start = line.index(_SECRET)
    # Fewer than the 20 characters the snippet pass needs would remain after the cut.
    assert start < 159 < start + 20
    snippet = _excerpt([line], 1)
    cleaned = Evidence(signal="s", description="d", snippet=snippet).snippet or ""
    assert _SECRET[:6] not in snippet and _SECRET[:6] not in cleaned


def test_a_random_literal_has_no_upper_length_bound() -> None:
    long_secret = (_SECRET * 160)[:5000]
    assert looks_random(long_secret)
    assert withhold_random_literals(f'token = "{long_secret}"') == f'token = "{REDACTED}"'


def _cut_whole_line(text: str, width: int) -> str:
    """The excerpt the whole line read before the cut gives: the reference for the bounded read."""
    text = withhold_random_literals(text)
    return text if len(text) <= width else text[: width - 1] + "\u2026"


# Separators carry no literal character, so every run of literal characters starts at a quote
# and is no longer than the generated body: a literal always fits the lookahead.
_LINE_PART = st.one_of(
    st.text(alphabet=" .=()+,;:\u2026", min_size=1, max_size=40),
    st.builds(
        lambda quote, body, close: quote + body + close,
        st.sampled_from(['"', "'", "`"]),
        st.text(alphabet=_BASE62 + "_-+/=", min_size=1, max_size=200),
        st.sampled_from(['"', "'", "`", "", "."]),
    ),
)


@given(parts=st.lists(_LINE_PART, min_size=1, max_size=80), width=st.sampled_from([40, 160]))
@settings(max_examples=300, deadline=5000)
def test_a_bounded_read_cuts_a_line_as_reading_the_whole_line_does(parts: list[str], width: int) -> None:
    line = "".join(parts)
    assert withhold_random_literals_cut(line, width) == _cut_whole_line(line, width)


def test_a_literal_the_shortened_excerpt_reaches_is_judged_before_it_shows() -> None:
    """A withheld literal shortens the line, so the excerpt shows text from past its width.

    A literal there must still be judged before it shows: a fixed window of the first
    ``width + 256`` characters ends inside this second literal, leaving fewer than the 20
    characters the snippet pass needs, and the shortened excerpt showed its start.
    """
    from shadowscan.connectors.code.filesystem import _excerpt

    first = (_SECRET * 10)[:300]
    second = _SECRET.swapcase()[::-1]
    assert looks_random(first) and looks_random(second)
    head = f'x = "{first}" + '
    line = head + "(" * (400 - len(head)) + f'"{second}" + y' + " ;" * 200
    assert line.index(second) < 416 < line.index(second) + 20
    snippet = _excerpt([line], 1)
    cleaned = Evidence(signal="s", description="d", snippet=snippet).snippet or ""
    assert second[:6] not in snippet and second[:6] not in cleaned
    assert snippet.count(REDACTED) == 2 and snippet.endswith("\u2026") and len(snippet) == 160


def test_a_withheld_literal_running_past_the_part_read_ends_the_excerpt() -> None:
    from shadowscan.connectors.code.filesystem import _excerpt

    long_secret = (_SECRET * 40)[:1200]
    line = f'blob = "{long_secret}"; other = 1'
    # Where the literal ends is not read, so nothing after its marker can show: not the
    # remainder of the literal, nor what follows it.
    assert _excerpt([line], 1) == f'blob = "{REDACTED}\u2026'
    assert _excerpt([f'blob = "{long_secret[:200]}"; other = 1' + " " * 300], 1).startswith(
        f'blob = "{REDACTED}"; other = 1'
    )
