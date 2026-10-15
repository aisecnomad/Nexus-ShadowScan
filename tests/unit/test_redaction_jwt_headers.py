"""JWTs whose header JSON is written with whitespace, which does not encode to 'eyJ'."""

from __future__ import annotations

import base64
import time

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _token(header: bytes) -> str:
    return ".".join([_b64url(header), _b64url(b'{"sub":"agent"}'), _b64url(bytes(range(32)))])


@pytest.mark.parametrize(
    "header",
    [
        b' {"alg":"HS256"}',
        b'{ "alg":"HS256"}',
        b'{\n  "alg": "RS256"\n}',
        b'\t{"alg":"none"}',
        b'\n{"alg":"ES256"}',
    ],
)
@pytest.mark.parametrize(
    "template", ["{}", "# issued: {}", "x-{}", "%2F{}", "\\n{}", "a.{}", "密钥{}", '"{}"']
)
def test_jwts_with_whitespace_in_the_header_are_redacted(header, template):
    # PyJWT and the identity.jwt decoder accept these headers.
    token = _token(header)
    assert not token.startswith("eyJ")
    result = sanitize_text(template.format(token))
    assert token not in result and REDACTED in result
    assert _b64url(header)[:12] not in result


@pytest.mark.parametrize(
    "text",
    [
        "release-candidate-version.1.2",
        "com.example.package.ClassName.method",
        "abcdefghijklmnopqrstuvwxyz.abc.def",
    ],
)
def test_dotted_values_that_are_not_tokens_are_kept(text):
    assert sanitize_text(text) == text


def test_a_dotted_json_object_without_alg_is_kept():
    value = ".".join([_b64url(b' {"name":"build"}'), _b64url(b'{"x":1}'), _b64url(b"abcdefghijkl")])
    assert sanitize_text(value) == value


def test_hostile_dotted_runs_stay_fast():
    started = time.monotonic()
    for shape in ("-IHsi" * 100_000 + ".a.b", "IHsiCQ" * 50_000 + ".x.y", ("x" * 20 + ".") * 50_000):
        try:
            sanitize_text(shape)
        except ValueError:
            pass  # SanitizationLimitError: the value is omitted and the scan incomplete
    assert time.monotonic() - started < 20
