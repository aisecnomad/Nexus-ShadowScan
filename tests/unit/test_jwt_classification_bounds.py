"""identity.jwt: tokens with unusual headers, inert verification options and claim bounds."""

from __future__ import annotations

import base64
import json

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.identity.jwt import JwtConnector


def _segment(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _unsigned(header: dict, claims: dict) -> str:
    return f"{_segment(header)}.{_segment(claims)}."


def _run(index, tokens, **config):
    ctx = ConnectorContext(config={"tokens": tokens, **config}, index=index)
    return JwtConnector(ctx).run(), ctx


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": 123},
        {"alg": "none", "kid": {"x": 1}},
        {"alg": "none", "crit": ["exp"], "exp": 1},
    ],
)
def test_a_token_with_an_odd_header_is_still_classified_as_unverified(index, header):
    findings, ctx = _run(index, [_unsigned(header, {"sub": "svc-bot", "iss": "https://idp.example"})])
    (finding,) = findings
    assert finding.metadata["signature_verified"] is False
    assert finding.metadata["kid"] is None
    assert not ctx.stats.errors


@pytest.mark.parametrize(
    "config", [{"expected_issuer": "https://idp.example"}, {"allowed_algorithms": ["RS256"]}]
)
def test_verification_options_without_a_key_set_are_refused(index, config):
    findings, ctx = _run(index, [_unsigned({"alg": "none"}, {"sub": "x"})], **config)
    assert findings == []
    assert ctx.stats.incomplete
    assert any("require jwks_url" in message for message in ctx.stats.errors)


def test_verification_options_without_a_key_set_raise_from_analyze(index):
    connector = JwtConnector(ConnectorContext(config={"expected_issuer": "https://idp.example"}, index=index))
    with pytest.raises(ConnectorError, match="require jwks_url"):
        list(connector.analyze([{"token": _unsigned({"alg": "none"}, {"sub": "x"})}]))


def test_agent_claim_values_and_claim_names_are_bounded(index):
    claims = {"sub": "svc", "agent_id": "A" * 60_000, **{f"c{n:03d}" + "n" * 100: 1 for n in range(150)}}
    (finding,), _ = _run(index, [_unsigned({"alg": "none"}, claims)])
    assert len(finding.metadata["agent_claims"]["agent_id"]) <= 200
    assert len(finding.metadata["claim_names"]) == 100
    assert all(len(name) <= 64 for name in finding.metadata["claim_names"])


def test_a_nested_token_cut_by_the_kid_and_claim_name_bounds_is_still_withheld(index):
    # A token in the kid or in a claim name, where the 200- and 64-character cuts fall
    # inside its payload: shortened first, it kept two of its three segments and no
    # longer looked like a token, so its header and part of its payload were reported.
    nested = ".".join(
        (
            _segment({"alg": "HS256", "typ": "JWT"}),
            _segment({"sub": "nested-service-subject", "scope": "admin write delete"}),
            "s" * 43,
        )
    )
    header_segment, payload_segment, _ = nested.split(".")
    kid = "k" * 120 + " " + nested
    name = "n " + nested
    for text, bound in ((kid, 200), (name, 64)):
        payload_start = text.index(payload_segment)
        assert payload_start < bound < payload_start + len(payload_segment)
    (finding,), _ = _run(index, [_unsigned({"alg": "none", "kid": kid}, {"sub": "svc", name: 1})])
    reported = json.dumps([finding.metadata["kid"], finding.metadata["claim_names"]])
    assert header_segment not in reported
    assert payload_segment[:12] not in reported
    assert finding.metadata["kid"] == "k" * 120 + " [REDACTED]"
    assert finding.metadata["claim_names"] == ["n [REDACTED]", "sub"]
