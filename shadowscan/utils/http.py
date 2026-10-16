"""Small HTTP helper with retries, rate-limit handling and pagination helpers.

Transport invariants:

* URL validation is preflight only. The HTTPS connection resolves the host
  once and connects to a numeric address while retaining the hostname for TLS
  verification. By default it rejects every private or metadata address in
  the answer set. The trusted ``allow_private_origin`` opt-in (scan-wide or
  for one connector; the operator's ``--deny-private-origin`` overrides both)
  lifts only that rejection: the numeric connection and TLS hostname
  verification still apply.
* Each client owns a copied urllib3 pool-class mapping. Proxies and replacement
  adapters are refused so an origin-specific pool cannot bypass destination
  checks. An injected session that is neither a ``requests.Session`` nor a
  ``unittest.mock`` double is refused, since it would skip those checks.
* The acquisition deadline covers DNS completion, TCP/TLS, request transmission
  and response headers. DNS itself cannot be interrupted, so it runs in a
  worker the request waits on for at most ``_RESOLVE_TIMEOUT``, less when the
  client timeout or the remaining budget is shorter; a late answer is
  discarded and cannot start a connection. A spent budget refuses without
  starting a worker, and at most ``_MAX_RESOLVER_THREADS`` workers run at once.
  Socket operations use the remaining monotonic budget.
* The whole-body read deadline is separate from the per-read socket timeout.
  Expiry shuts down a still-owned response socket, and the response must never
  be treated as complete after that shutdown.
* urllib3 returns a keep-alive connection to its pool during the body-ending
  read. The watchdog and release wrapper therefore coordinate before a socket
  is interrupted; changing that release contract can affect another request.

Keep ``tests/unit/test_http_contracts.py`` in sync with any urllib3 upgrade:
these checks are intentional tripwires for private transport hooks used here.
"""

from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import json
import logging
import math
import os
import random
import re
import socket
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ConnectTimeout,
    ContentDecodingError,
    InvalidHeader,
    ReadTimeout,
    RequestException,
    SSLError,
    Timeout,
)
from requests.utils import check_header_validity
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

from shadowscan import __version__
from shadowscan.utils.redaction import sanitize_text

log = logging.getLogger("shadowscan.http")

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
# A per-read socket timeout does not bound a response body: a server can send one
# byte just inside every timeout. Each body must also finish within this multiple
# of the client timeout (60 seconds by default).
READ_DEADLINE_FACTOR = 2
MAX_RETRY_DELAY = 120
RETRY_STATUSES = {429, 500, 502, 503, 504}
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

_allow_private_origin: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "shadowscan_allow_private_origin", default=False
)
_ca_bundle: contextvars.ContextVar[str | None] = contextvars.ContextVar("shadowscan_ca_bundle", default=None)
# (monotonic deadline, cancellation event) of the connector the current worker runs.
_request_limits: contextvars.ContextVar[tuple[float | None, threading.Event | None]] = contextvars.ContextVar(
    "shadowscan_request_limits", default=(None, None)
)
_acquisition_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "shadowscan_http_acquisition_deadline", default=None
)


class _SocketDeadline:
    """Interrupt acquisition while this pool checkout still owns its socket.

    The timer never closes a descriptor or touches a returned pool connection.
    ``finish`` cancels and joins it before ``_make_request`` returns, so an
    expiring request cannot shut down a socket reused by another request.
    DNS runs in a bounded worker (``_resolve_bounded``): the resolver call
    itself cannot be killed, but the request stops waiting at its budget and a
    late resolution cannot proceed to a connection. TLS uses the remaining
    socket timeout.
    """

    def __init__(self, connection: Any, deadline: float):
        self.connection = connection
        self.deadline = deadline
        self.socket: socket.socket | None = None
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._finished = False
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._abort)
        self._timer.name = "shadowscan-http-acquisition"
        self._timer.daemon = True
        self._timer.start()

    def _abort(self) -> None:
        with self._lock:
            if self._finished:
                return
            self.expired.set()
            # During numeric connect the socket is not yet assigned to the
            # connection. After TLS wrapping, its live SSLSocket takes priority.
            active = self.connection.sock or self.socket
            if active is not None:
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    active.shutdown(socket.SHUT_RDWR)

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if self.expired.is_set() or remaining <= 0:
            raise ValueError("HTTP request exceeds the acquisition deadline")
        return remaining

    def socket_timeout(self, timeout: Any) -> float:
        remaining = self.remaining()
        return min(float(timeout), remaining) if isinstance(timeout, (float, int)) else remaining

    def watch_socket(self, active: socket.socket) -> None:
        with self._lock:
            self.socket = active
        self.remaining()

    def finish(self) -> None:
        with self._lock:
            self._finished = True
        self._timer.cancel()
        self._timer.join()


def _validate_headers(headers: Any, *, allow_removal: bool = False) -> None:
    """Reject malformed headers without putting their names or values in errors.

    requests and the underlying HTTP transport quote invalid input in errors.
    Header names can contain credentials too, so diagnostics are deliberately
    independent of both. Per-request None retains requests' removal semantics.
    """
    if headers is None:
        return
    if not isinstance(headers, Mapping):
        raise ValueError("HTTP headers must be a mapping")
    for name, value in headers.items():
        try:
            encoded_name = name.encode("ascii") if isinstance(name, str) else name
            if not isinstance(encoded_name, bytes) or not _HEADER_NAME.fullmatch(encoded_name):
                raise ValueError
            if allow_removal and value is None:
                continue
            check_header_validity((name, value))
            encoded_value = value.encode("latin-1") if isinstance(value, str) else value
            if any(byte < 32 and byte != 9 or byte == 127 for byte in encoded_value):
                raise ValueError
        except (InvalidHeader, TypeError, ValueError, UnicodeError):
            raise ValueError("HTTP header contains invalid characters or types") from None


def _positive_byte_limit(value: int | None, default: int) -> int:
    limit = default if value is None else value
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("max_bytes must be a positive integer")
    return limit


def _validated_ca_bundle(path: Any) -> str:
    """An explicit, operator-supplied PEM bundle: an existing regular file, nothing else."""
    message = "ca_bundle must be a path to an existing regular file"
    if not isinstance(path, str) or not path or "\0" in path:
        raise ValueError(message)
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        raise ValueError(message) from None
    if not regular:
        raise ValueError(message)
    return os.path.abspath(path)


def _read_deadline(timeout: float) -> float:
    """Derive the whole-body read deadline from the per-read client timeout."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a positive finite number of seconds")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive finite number of seconds")
    return float(timeout) * READ_DEADLINE_FACTOR


# getaddrinfo has no timeout or cancellation interface of its own: a stalled
# system resolver would otherwise hold the calling worker past every
# cooperative deadline check. This bounds the wait. At connection the client
# timeout and the acquisition deadline tighten it; in the validate_url
# preflight the connector deadline and, for HttpClient, its timeout and
# deadline (``dns_budget``) do.
_RESOLVE_TIMEOUT = 20.0
# An abandoned worker keeps its thread until the system resolver returns. The
# cap stops a stalled resolver from accumulating them without bound: once every
# slot is held, a lookup waits for one within its budget, then fails closed.
_MAX_RESOLVER_THREADS = 32
_resolver_slots = threading.BoundedSemaphore(_MAX_RESOLVER_THREADS)
_RESOLVE_EXPIRED = "DNS resolution did not complete within the deadline"


def _resolve_bounded(host: str, port: int, budget: float, **kwargs: Any) -> list[Any]:
    """Run ``socket.getaddrinfo`` in a worker thread, waiting at most ``budget``.

    The resolver call itself cannot be interrupted: on timeout the worker is
    abandoned (it holds only its arguments and ends with the call) and
    ``TimeoutError`` is raised, so a result that arrives late is discarded
    with the worker, never used. A resolver error is re-raised in the caller.
    A spent (or NaN) budget, or no free worker slot within it, raises
    ``TimeoutError`` before any thread starts, so an expired deadline never
    races a fast answer.
    """
    if not budget > 0:
        raise TimeoutError(_RESOLVE_EXPIRED)
    end = time.monotonic() + budget
    # Bound to a local so the worker releases the semaphore it acquired.
    slots = _resolver_slots
    if not slots.acquire(timeout=budget):
        raise TimeoutError(_RESOLVE_EXPIRED)
    remaining = end - time.monotonic()
    if remaining <= 0:
        slots.release()
        raise TimeoutError(_RESOLVE_EXPIRED)
    answers: list[list[Any]] = []
    failures: list[BaseException] = []
    done = threading.Event()
    # The slot is returned exactly once: by the worker when it ends, or below
    # when no worker started. An interrupt can leave start() after the thread
    # is already running, and then both sides reach the release.
    freed = threading.Lock()

    def free_slot() -> None:
        if freed.acquire(blocking=False):
            slots.release()

    def resolve() -> None:
        try:
            answers.append(socket.getaddrinfo(host, port, **kwargs))
        except Exception as exc:  # noqa: BLE001 - delivered to the waiting caller below
            failures.append(exc)
        finally:
            done.set()
            free_slot()

    try:
        worker = threading.Thread(target=resolve, name="shadowscan-http-resolve", daemon=True)
        worker.start()
    except BaseException:
        # RuntimeError ("can't start new thread"), MemoryError from building the
        # thread or its state, or an interrupt: a slot no worker returns would
        # be lost for good, and after every slot every lookup would refuse.
        free_slot()
        raise
    if not done.wait(remaining):
        raise TimeoutError(_RESOLVE_EXPIRED)
    if failures:
        raise failures[0]
    if not answers:  # the worker died without an answer or an error
        raise TimeoutError(_RESOLVE_EXPIRED)
    return answers[0]


def _read_watchdog(
    resp: requests.Response, seconds: float, expired: threading.Event
) -> threading.Timer | None:
    """Abort a body read that is still blocked when its deadline passes.

    urllib3 fills a whole chunk before returning it, so a server dripping bytes
    inside the socket timeout would otherwise hold the worker until the connector
    deadline abandons it. Shutting the socket down for reading wakes the blocked
    read; ``expired`` tells the reader that any end of body it then sees is not a
    complete response.

    urllib3 returns the connection to the pool during the read that ends the
    body, before the reader regains control, and its ``shutdown()`` checks for
    that without a lock. A pooled socket may already carry another request on
    this session, so a release waits for a shutdown in progress, and the
    watchdog leaves alone a body whose connection was released before it fired.
    """
    raw: Any = resp.raw
    shutdown = getattr(raw, "shutdown", None)
    if not callable(shutdown):
        return None
    lock = threading.Lock()
    released = False
    release = getattr(raw, "release_conn", None)
    if callable(release):

        def release_conn() -> None:
            nonlocal released
            with lock:
                released = True
                release()

        raw.release_conn = release_conn

    def abort() -> None:
        with lock:
            if released:
                return
            expired.set()
            # urllib3 refuses to shut down a connection that is already closed.
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                shutdown()

    timer = threading.Timer(seconds, abort)
    timer.daemon = True
    timer.start()
    return timer


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Do not let duplicate fields overwrite observations or pagination state."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # API responses may reflect credentials in field names or values.
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON number")
    return number


METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
METADATA_NETS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.169.253/32"),
    ipaddress.ip_network("169.254.169.250/32"),
    # Azure's wire server and metadata endpoint: a public-looking address that is link-local to the VM.
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


def set_allow_private_origin(enabled: bool) -> contextvars.Token[bool]:
    """Set the current worker's policy; callers must reset the returned token."""
    if not isinstance(enabled, bool):
        raise TypeError("allow_private_origin must be a boolean")
    return _allow_private_origin.set(enabled)


def reset_allow_private_origin(token: contextvars.Token[bool]) -> None:
    """Restore the policy after a connector finishes, including failed scans."""
    _allow_private_origin.reset(token)


def set_ca_bundle(path: str | None) -> contextvars.Token[str | None]:
    """Trust only this PEM bundle for clients the current worker creates.

    TLS verification stays on; the bundle replaces the default CA store, so it
    suits scans of private endpoints behind internal PKI. Callers must reset
    the returned token.
    """
    return _ca_bundle.set(None if path is None else _validated_ca_bundle(path))


def get_ca_bundle() -> str | None:
    """Return the validated PEM bundle configured for the current worker, if any."""
    return _ca_bundle.get()


def reset_ca_bundle(token: contextvars.Token[str | None]) -> None:
    _ca_bundle.reset(token)


def set_request_deadline(
    deadline: float | None, cancelled: threading.Event | None
) -> contextvars.Token[tuple[float | None, threading.Event | None]]:
    """Let clients created by the current worker stop retrying once the scan is over.

    ``deadline`` is a ``time.monotonic()`` value and ``cancelled`` the
    connector's cancellation event. Callers must reset the returned token.
    """
    return _request_limits.set((deadline, cancelled))


def reset_request_deadline(token: contextvars.Token[tuple[float | None, threading.Event | None]]) -> None:
    _request_limits.reset(token)


# RFC 6052 well-known NAT64 prefix. A DNS64 resolver maps every IPv4 name into it, so
# IPv6-only runners reach public APIs only through it. The address is judged by the IPv4
# address the translator connects to. The local-use 64:ff9b:1::/48 prefix stays blocked.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
        if addr in _NAT64_WELL_KNOWN:
            return _blocked_ip(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
        embedded = addr.ipv4_mapped or addr.sixtofour
        if embedded is not None and _blocked_ip(embedded):
            return True
        if addr.teredo and any(_blocked_ip(part) for part in addr.teredo):
            return True
    return bool(
        not addr.is_global
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
        # Deprecated site-local fec0::/10 is still routed inside some networks; ipaddress calls it global.
        or (isinstance(addr, ipaddress.IPv6Address) and addr.is_site_local)
        or any(addr in net for net in METADATA_NETS)
    )
