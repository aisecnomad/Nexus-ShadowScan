"""DNS resolution is bounded: a stalled system resolver fails the request closed.

``socket.getaddrinfo`` has no timeout of its own, so ``_resolve_bounded`` runs
it in a worker thread and abandons the worker at its budget. These tests pin
the fail-closed contract at both call sites — the ``validate_url`` preflight
and the connection-time re-resolution — and that a late answer is discarded,
never connected to.
"""

from __future__ import annotations

import socket
import threading
import time
from unittest.mock import Mock

import pytest
from urllib3.exceptions import NameResolutionError

from shadowscan.utils.http import (
    HttpClient,
    _PublicHTTPSConnection,
    _resolve_bounded,
    reset_request_deadline,
    set_request_deadline,
    validate_url,
)

PUBLIC_ANSWER = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]


def _stalled_resolver(release: threading.Event, answer: list = PUBLIC_ANSWER):
    """A resolver that blocks until the test releases it, then answers."""
    calls: list[tuple[str, int]] = []

    def resolver(host: str, port: int, **kwargs: object) -> list:
        calls.append((host, port))
        release.wait(10)
        return answer

    return resolver, calls


def test_stalled_resolver_fails_the_url_preflight_closed(monkeypatch):
    release = threading.Event()
    resolver, calls = _stalled_resolver(release)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http._RESOLVE_TIMEOUT", 0.05)
    started = time.monotonic()
    try:
        with pytest.raises(ValueError, match="DNS resolution .* did not complete"):
            validate_url("https://stalled.example/path")
    finally:
        release.set()
    # The caller stopped waiting at the budget, not at the resolver's leisure.
    assert time.monotonic() - started < 5
    assert calls == [("stalled.example", 443)]


def test_stalled_resolver_fails_the_connection_closed_without_a_socket(monkeypatch):
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    factory = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", factory)
    monkeypatch.setattr("shadowscan.utils.http._RESOLVE_TIMEOUT", 0.05)
    connection = _PublicHTTPSConnection("stalled.example", timeout=5)
    try:
        with pytest.raises(NameResolutionError):
            connection._new_conn()
    finally:
        release.set()
    # The late answer is discarded with its worker: nothing is connected.
    time.sleep(0.05)
    factory.assert_not_called()


def test_expired_connector_deadline_leaves_no_resolution_budget(monkeypatch):
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    token = set_request_deadline(time.monotonic() - 1, None)
    started = time.monotonic()
    try:
        with pytest.raises(ValueError, match="DNS resolution .* did not complete"):
            validate_url("https://stalled.example/path")
    finally:
        reset_request_deadline(token)
        release.set()
    # The full _RESOLVE_TIMEOUT (unpatched here) was never waited out.
    assert time.monotonic() - started < 5


def test_resolver_errors_keep_their_existing_meaning(monkeypatch):
    # NXDOMAIN stays a preflight pass: the connection-time check is the
    # authority for names that do not resolve at all.
    monkeypatch.setattr(
        "shadowscan.utils.http.socket.getaddrinfo", Mock(side_effect=socket.gaierror("NXDOMAIN"))
    )
    assert validate_url("https://unknown.example/x") == "https://unknown.example/x"
    with pytest.raises(NameResolutionError):
        _PublicHTTPSConnection("unknown.example", timeout=5)._new_conn()


def test_bounded_resolver_returns_prompt_answers_unchanged(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(return_value=PUBLIC_ANSWER))
    assert _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER


def test_duck_typed_session_is_refused():
    class DuckSession:
        headers: dict[str, str] = {}
        proxies: dict[str, str] = {}

    with pytest.raises(TypeError, match="session must be a requests.Session"):
        HttpClient("https://api.example.com/v1", session=DuckSession())  # type: ignore[arg-type]


def test_mock_session_stand_in_stays_accepted():
    # The documented test seam: unittest.mock doubles carry no real transport.
    client = HttpClient("https://api.example.com/v1", session=Mock(headers={}))
    assert client.base_url == "https://api.example.com/v1"
