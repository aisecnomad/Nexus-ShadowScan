"""DNS resolution is bounded: a stalled system resolver fails the request closed.

``socket.getaddrinfo`` has no timeout of its own, so ``_resolve_bounded`` runs
it in a worker thread and abandons the worker at its budget. These tests pin
the fail-closed contract at both call sites — the ``validate_url`` preflight
and the connection-time re-resolution — and that a late answer is discarded,
never connected to; that a spent budget starts no worker and the abandoned
workers are capped; that an ``HttpClient`` preflight waits no longer than
the client's timeout or deadline; and which exception an ``HttpClient`` caller
gets when the connection-time lookup stalls.
"""

from __future__ import annotations

import json
import math
import socket
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from urllib3.exceptions import NameResolutionError

from shadowscan.utils import http as http_module
from shadowscan.utils.http import (
    DestinationUnresolved,
    HttpClient,
    _PublicHTTPSConnection,
    _resolve_bounded,
    reset_request_deadline,
    resolve_destination,
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


class _CountingThread(threading.Thread):
    """``threading.Thread`` that records every resolver worker it starts."""

    started: list[threading.Thread]

    def start(self) -> None:
        if self.name == "shadowscan-http-resolve":
            type(self).started.append(self)
        super().start()


@pytest.fixture
def resolver_threads(monkeypatch) -> list[threading.Thread]:
    started: list[threading.Thread] = []
    counting = type("CountingThread", (_CountingThread,), {"started": started})
    monkeypatch.setattr("shadowscan.utils.http.threading.Thread", counting)
    return started


def _live_resolver_threads() -> int:
    return sum(1 for thread in threading.enumerate() if thread.name == "shadowscan-http-resolve")


def test_spent_budget_refuses_without_starting_a_resolver(monkeypatch, resolver_threads):
    # An expired deadline refuses deterministically: no worker starts, so a fast
    # answer cannot win the race against a zero-length wait and be used.
    resolver = Mock(return_value=PUBLIC_ANSWER)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    for budget in (0.0, -1.0, math.nan):
        with pytest.raises(TimeoutError):
            _resolve_bounded("fast.example", 443, budget, proto=socket.IPPROTO_TCP)
    token = set_request_deadline(time.monotonic() - 1, None)
    try:
        for index in range(50):
            with pytest.raises(ValueError, match="DNS resolution .* did not complete"):
                validate_url(f"https://h{index}.example/path")
            # The clone pin lookup shares the bounded resolver and refuses the same way.
            with pytest.raises(DestinationUnresolved):
                resolve_destination(f"h{index}.example", 443)
    finally:
        reset_request_deadline(token)
    assert resolver_threads == []
    resolver.assert_not_called()


def test_stalled_resolver_workers_are_capped_and_extra_lookups_fail_closed(monkeypatch, resolver_threads):
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    slots = threading.BoundedSemaphore(3)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http._resolver_slots", slots)
    before = _live_resolver_threads()
    try:
        for index in range(20):
            with pytest.raises(TimeoutError):
                _resolve_bounded(f"h{index}.example", 443, 0.05, proto=socket.IPPROTO_TCP)
        # Three abandoned workers hold every slot; the other 17 lookups waited
        # their budget for one and were refused without a thread, never allowed.
        assert len(resolver_threads) == 3
        assert _live_resolver_threads() - before <= 3
    finally:
        release.set()
    for worker in resolver_threads:
        worker.join(10)
        assert not worker.is_alive()
    # Each worker returned its slot when the resolver let it go.
    assert all(slots.acquire(blocking=False) for _ in range(3))
    for _ in range(3):
        slots.release()
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(return_value=PUBLIC_ANSWER))
    assert _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER


def test_lookup_waits_within_its_budget_for_a_slot_to_free(monkeypatch):
    # The cap delays a lookup, it does not refuse one whose budget outlasts a
    # busy slot: normal concurrency still resolves.
    release = threading.Event()
    resolver, calls = _stalled_resolver(release)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http._resolver_slots", threading.BoundedSemaphore(1))
    with pytest.raises(TimeoutError):
        _resolve_bounded("held.example", 443, 0.2, proto=socket.IPPROTO_TCP)
    timer = threading.Timer(0.1, release.set)
    timer.start()
    try:
        assert _resolve_bounded("next.example", 443, 10.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER
    finally:
        release.set()
        timer.join()
    assert calls == [("held.example", 443), ("next.example", 443)]


@pytest.mark.parametrize("stage", ["construct", "start"])
@pytest.mark.parametrize("failure", [RuntimeError, MemoryError])
def test_a_worker_that_cannot_start_returns_its_slot(monkeypatch, failure, stage):
    # The OS refusing a thread raises RuntimeError; CPython raises MemoryError when it
    # cannot allocate the thread or its state. Only RuntimeError returned the slot, so
    # after 32 such failures every later lookup refused for the life of the process.
    class Unstartable(threading.Thread):
        def __init__(self, *args, **kwargs) -> None:
            if stage == "construct":
                raise failure("can't start new thread")
            super().__init__(*args, **kwargs)

        def start(self) -> None:
            raise failure("can't start new thread")

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr("shadowscan.utils.http._resolver_slots", slots)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(return_value=PUBLIC_ANSWER))
    with monkeypatch.context() as patched:
        patched.setattr("shadowscan.utils.http.threading.Thread", Unstartable)
        for _ in range(3):
            with pytest.raises(failure):
                _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP)
    assert _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER


class _Interrupted(BaseException):
    """An interrupt delivered while ``Thread.start`` waits for the new thread."""


def test_a_worker_interrupted_after_it_started_returns_its_slot_once(monkeypatch):
    # The worker ran and returned its slot; the failed start must not return it again
    # (a bounded semaphore refuses that, replacing the interrupt with ValueError).
    class StartedThenInterrupted(threading.Thread):
        def start(self) -> None:
            super().start()
            self.join(10)
            raise _Interrupted

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr("shadowscan.utils.http._resolver_slots", slots)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(return_value=PUBLIC_ANSWER))
    with monkeypatch.context() as patched:
        patched.setattr("shadowscan.utils.http.threading.Thread", StartedThenInterrupted)
        with pytest.raises(_Interrupted):
            _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP)
    assert slots.acquire(blocking=False) and not slots.acquire(blocking=False)
    slots.release()
    assert _resolve_bounded("fast.example", 443, 5.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER


def test_a_lookup_whose_budget_ends_after_it_takes_a_slot_returns_it(monkeypatch):
    # The slot is free, but the budget is spent once it is taken (a lookup right at
    # its deadline edge): the lookup refuses without a worker and must give the slot
    # back, or such lookups would drain the cap and every later one would refuse.
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr("shadowscan.utils.http._resolver_slots", slots)
    resolver = Mock(return_value=PUBLIC_ANSWER)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    ticks = iter(float(tick) for tick in range(1000))
    with monkeypatch.context() as patched:
        # Each reading of the clock is a second later: the budget ends between them.
        patched.setattr("shadowscan.utils.http.time", SimpleNamespace(monotonic=lambda: next(ticks)))
        for _ in range(3):
            with pytest.raises(TimeoutError):
                _resolve_bounded("edge.example", 443, 0.5, proto=socket.IPPROTO_TCP)
    resolver.assert_not_called()
    assert _resolve_bounded("fast.example", 443, 1.0, proto=socket.IPPROTO_TCP) == PUBLIC_ANSWER


def _response(data: object, *, status: int = 200, headers: dict[str, str] | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result._content_consumed = True
    result.headers.update(headers or {})
    return result


def _budget_spy(monkeypatch) -> list[float | None]:
    budgets: list[float | None] = []
    real = http_module.validate_url

    def spy(url, origin=None, *, allow_private=None, dns_budget=None):
        budgets.append(dns_budget)
        return real(url, origin, allow_private=allow_private, dns_budget=dns_budget)

    monkeypatch.setattr("shadowscan.utils.http.validate_url", spy)
    return budgets


@pytest.mark.parametrize("deadline", [None, 60.0])
def test_every_client_preflight_waits_no_longer_than_the_timeout_or_deadline(monkeypatch, deadline):
    # The request, redirect and pagination preflights all pass the client's
    # timeout, cut to its remaining deadline, as the DNS budget.
    budgets = _budget_spy(monkeypatch)
    session = Mock(headers={})
    session.request.side_effect = [
        _response(None, status=302, headers={"Location": "/moved"}),
        _response({"ok": True}),
        _response(
            {"items": [{"id": 1}]}, headers={"Link": '<https://api.example.com/v1/items?page=2>; rel="next"'}
        ),
        _response({"items": [{"id": 2}]}),
        _response({"value": [{"id": 3}], "@odata.nextLink": "https://api.example.com/v1/values?page=2"}),
        _response({"value": [{"id": 4}]}),
    ]
    limit = None if deadline is None else time.monotonic() + deadline
    http = HttpClient("https://api.example.com/v1", timeout=120, session=session, deadline=limit)
    assert http.get_json("/redirected") == {"ok": True}
    assert list(http.paginate_link("/items", item_key="items")) == [{"id": 1}, {"id": 2}]
    assert list(http.paginate_odata("/values")) == [{"id": 3}, {"id": 4}]
    # get_json: the request and the redirect; each paginator: its origin, then
    # for each of two pages its own check and the request's.
    assert len(budgets) == 2 + 2 * (1 + 2 * 2)
    if deadline is None:
        assert budgets == [120.0] * len(budgets)
    else:
        assert all(budget is not None and 0 < budget <= deadline for budget in budgets)


@pytest.mark.parametrize("bound", ["timeout", "deadline"])
def test_client_timeout_and_deadline_end_a_stalled_preflight(monkeypatch, bound):
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http._RESOLVE_TIMEOUT", 10.0)
    if bound == "timeout":
        client = HttpClient("https://stalled.example", timeout=0.05, max_retries=0)
    else:
        client = HttpClient("https://stalled.example", deadline=time.monotonic() + 0.05, max_retries=0)
    started = time.monotonic()
    try:
        with pytest.raises(ValueError, match="DNS resolution .* did not complete"):
            client.get("/x")
    finally:
        release.set()
    # Bounded by the client, not the (patched) 10 s resolver ceiling.
    assert time.monotonic() - started < 5


def test_client_timeout_bounds_the_connection_time_lookup(monkeypatch):
    budgets: list[float] = []
    real = http_module._resolve_bounded

    def spy(host, port, budget, **kwargs):
        budgets.append(budget)
        return real(host, port, budget, **kwargs)

    monkeypatch.setattr("shadowscan.utils.http._resolve_bounded", spy)
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    try:
        with pytest.raises(NameResolutionError):
            _PublicHTTPSConnection("stalled.example", timeout=0.05)._new_conn()
    finally:
        release.set()
    assert budgets == [0.05]


@pytest.mark.parametrize("bound", ["lookup", "acquisition-deadline"])
def test_client_callers_see_a_stalled_connection_time_lookup_as_documented(monkeypatch, bound):
    # docs/api/http.md: urllib3's NameResolutionError reaches an HttpClient caller as
    # requests.ConnectionError, and as ValueError once the acquisition deadline has passed.
    # A numeric host has no preflight lookup, so only the connection-time lookup stalls.
    release = threading.Event()
    resolver, _ = _stalled_resolver(release)
    factory = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", factory)
    if bound == "lookup":
        # The lookup gives up long before the acquisition deadline (twice the timeout).
        monkeypatch.setattr("shadowscan.utils.http._RESOLVE_TIMEOUT", 0.05)
        client = HttpClient("https://8.8.8.8", timeout=5, max_retries=0)
        expected, message = requests.ConnectionError, "connection failure"
    else:
        client = HttpClient("https://8.8.8.8", timeout=5, deadline=time.monotonic() + 0.05, max_retries=0)
        expected, message = ValueError, "acquisition deadline"
    try:
        with pytest.raises(expected, match=message):
            client.get("/x")
    finally:
        release.set()
    factory.assert_not_called()
