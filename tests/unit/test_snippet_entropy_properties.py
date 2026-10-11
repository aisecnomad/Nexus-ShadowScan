"""Generated secrets in snippets are withheld whatever names or calls surround them."""

from __future__ import annotations

import string

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.models import Evidence  # noqa: E402
from shadowscan.utils.redaction import REDACTED  # noqa: E402
from shadowscan.utils.redaction_entropy import looks_random, withhold_random_literals  # noqa: E402

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
    assert snippet.endswith("\u2026") and _SECRET not in snippet
    cleaned = Evidence(signal="s", description="d", snippet=snippet).snippet
    assert cleaned is not None and _SECRET[:20] not in cleaned and REDACTED in cleaned


def test_a_random_literal_has_no_upper_length_bound() -> None:
    long_secret = (_SECRET * 160)[:5000]
    assert looks_random(long_secret)
    assert withhold_random_literals(f'token = "{long_secret}"') == f'token = "{REDACTED}"'
