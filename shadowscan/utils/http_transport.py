"""urllib3 connection and pool hooks for the legacy ``shadowscan.utils.http`` API.

Transport classes resolve mutable policy and socket dependencies from the legacy
module at call time. This keeps existing monkeypatches of ``http.socket``,
``http.time`` and policy helpers effective after the implementation split.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, cast

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError


def _http_core() -> Any:
    """The compatibility module remains the canonical source of mutable dependencies."""
    return sys.modules["shadowscan.utils.http"]


class _SocketDeadline:
    """Interrupt acquisition while this pool checkout still owns its socket.

    The timer never closes a descriptor or touches a returned pool connection.
    ``finish`` cancels and joins it before ``_make_request`` returns, so an
    expiring request cannot shut down a socket reused by another request.
    DNS runs in the caller: it cannot be killed safely, but a late resolution
    cannot proceed to a connection. TLS uses the remaining socket timeout.
    """

    def __init__(self, connection: Any, deadline: float):
        self.connection = connection
        self.deadline = deadline
        self.socket: Any = None
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._finished = False
        core = _http_core()
        self._timer = core.threading.Timer(max(0.0, deadline - core.time.monotonic()), self._abort)
        self._timer.name = "shadowscan-http-acquisition"
        self._timer.daemon = True
        self._timer.start()

    def _abort(self) -> None:
        core = _http_core()
        with self._lock:
            if self._finished:
                return
            self.expired.set()
            # During numeric connect the socket is not yet assigned to the
            # connection. After TLS wrapping, its live SSLSocket takes priority.
            active = self.connection.sock or self.socket
            if active is not None:
                with core.contextlib.suppress(OSError, RuntimeError, ValueError):
                    active.shutdown(core.socket.SHUT_RDWR)

    def remaining(self) -> float:
        core = _http_core()
        remaining = self.deadline - cast(float, core.time.monotonic())
        if self.expired.is_set() or remaining <= 0:
            raise ValueError("HTTP request exceeds the acquisition deadline")
        return remaining

    def socket_timeout(self, timeout: Any) -> float:
        remaining = self.remaining()
        return min(float(timeout), remaining) if isinstance(timeout, (float, int)) else remaining

    def watch_socket(self, active: Any) -> None:
        with self._lock:
            self.socket = active
        self.remaining()

    def finish(self) -> None:
        with self._lock:
            self._finished = True
        self._timer.cancel()
        self._timer.join()


class _PublicHTTPSConnection(HTTPSConnection):
    """Resolve once, validate every answer, then connect a numeric sockaddr.

    TLS retains the original hostname for SNI and certificate verification.
    Checking the addresses inside _new_conn avoids the DNS check/use race of
    validating a URL before handing its hostname to requests for resolution.
    """

    allow_private_origin = False
    acquisition_guard: _SocketDeadline | None = None

    def _new_conn(self) -> Any:
        core = _http_core()
        guard = self.acquisition_guard
        if guard is not None:
            guard.remaining()
        host = self.host.rstrip(".")
        if not self.allow_private_origin and (core._blocked_host(host) or "%" in host):
            raise ValueError("Refusing private or cloud-metadata destination")
        try:
            addresses = core.socket.getaddrinfo(host, self.port or 443, type=core.socket.SOCK_STREAM)
        except core.socket.gaierror as exc:
            raise NameResolutionError(host, self, exc) from exc
        if guard is not None:
            guard.remaining()
        if not addresses:
            raise NewConnectionError(self, "DNS returned no usable addresses")
        # Reject mixed public/private results, not just the first DNS answer.
        for _, _, _, _, address in addresses:
            if not self.allow_private_origin and core._blocked_ip(core.ipaddress.ip_address(address[0])):
                raise ValueError("Refusing private or cloud-metadata destination")
        last_error: OSError | None = None
        for family, socktype, proto, _, address in addresses:
            connection: Any = None
            try:
                connection = core.socket.socket(family, socktype, proto)
                if guard is not None:
                    guard.watch_socket(connection)
                connection.settimeout(guard.socket_timeout(self.timeout) if guard else self.timeout)
                for option in self.socket_options or ():
                    connection.setsockopt(*option)
                if self.source_address:
                    connection.bind(self.source_address)
                connection.connect(address)
                if guard is not None:
                    # TLS follows this connect; give its handshake only the
                    # remaining acquisition time, not another full timeout.
                    connection.settimeout(guard.socket_timeout(self.timeout))
                return connection
            except ValueError:
                if connection is not None:
                    connection.close()
                raise
            except OSError as exc:
                last_error = exc
                if connection is not None:
                    connection.close()
        if isinstance(last_error, TimeoutError):
            raise ConnectTimeoutError(self, "HTTPS connection timed out") from last_error
        raise NewConnectionError(self, "HTTPS connection failed") from last_error


class _PrivateHTTPSConnection(_PublicHTTPSConnection):
    allow_private_origin = True


class _AcquisitionHTTPSConnectionPool(HTTPSConnectionPool):
    def _make_request(self, conn: Any, *args: Any, **kwargs: Any) -> Any:
        core = _http_core()
        deadline = core._acquisition_deadline.get()
        if deadline is None:
            return super()._make_request(conn, *args, **kwargs)
        guard = core._SocketDeadline(conn, deadline)
        conn.acquisition_guard = guard
        try:
            try:
                response = super()._make_request(conn, *args, **kwargs)
            except Exception:
                guard.finish()
                if guard.expired.is_set() or core.time.monotonic() >= deadline:
                    raise ValueError("HTTP request exceeds the acquisition deadline") from None
                raise
            guard.finish()
            if guard.expired.is_set() or core.time.monotonic() >= deadline:
                response.close()
                raise ValueError("HTTP request exceeds the acquisition deadline")
            return response
        finally:
            guard.finish()
            conn.acquisition_guard = None


class _PublicHTTPSConnectionPool(_AcquisitionHTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class _PrivateHTTPSConnectionPool(_AcquisitionHTTPSConnectionPool):
    ConnectionCls = _PrivateHTTPSConnection


class _DestinationPolicyAdapter(HTTPAdapter):
    def __init__(self, *, allow_private: bool):
        self.allow_private = allow_private
        super().__init__()

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **kwargs: Any) -> None:
        super().init_poolmanager(connections, maxsize, block=block, **kwargs)
        # urllib3's default mapping is shared; do not mutate another client's policy.
        self.poolmanager.pool_classes_by_scheme = dict(self.poolmanager.pool_classes_by_scheme)
        self.poolmanager.pool_classes_by_scheme["https"] = (
            _PrivateHTTPSConnectionPool if self.allow_private else _PublicHTTPSConnectionPool
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        raise ValueError("Proxies are unsupported by the destination-enforcing HTTP client")
