"""Tripwires for urllib3 internals used by the destination-enforcing transport."""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest
from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.response import HTTPResponse

from shadowscan.utils import http
from shadowscan.utils.http import (
    _AcquisitionHTTPSConnectionPool,
    _DestinationPolicyAdapter,
    _PrivateHTTPSConnection,
    _PrivateHTTPSConnectionPool,
    _PublicHTTPSConnection,
    _PublicHTTPSConnectionPool,
    _SocketDeadline,
)


def test_urllib3_request_and_response_hooks_remain_available() -> None:
    request_parameters = inspect.signature(HTTPSConnectionPool._make_request).parameters
    assert {"self", "conn", "method", "url"} <= set(request_parameters)
    assert callable(getattr(HTTPResponse, "shutdown", None))
    assert callable(getattr(HTTPResponse, "release_conn", None))


def test_destination_policy_pool_classes_use_urllib3_connection_hook() -> None:
    assert _PublicHTTPSConnectionPool.ConnectionCls is _PublicHTTPSConnection
    assert _PrivateHTTPSConnectionPool.ConnectionCls is _PrivateHTTPSConnection
    assert callable(_AcquisitionHTTPSConnectionPool._make_request)


def test_destination_policy_adapters_isolate_pool_class_mapping() -> None:
    first = _DestinationPolicyAdapter(allow_private=False)
    second = _DestinationPolicyAdapter(allow_private=True)
    ordinary = HTTPAdapter()
    try:
        first_classes = first.poolmanager.pool_classes_by_scheme
        second_classes = second.poolmanager.pool_classes_by_scheme
        ordinary_classes = ordinary.poolmanager.pool_classes_by_scheme
        assert first_classes is not second_classes
        assert first_classes is not ordinary_classes
        assert second_classes is not ordinary_classes
        assert first_classes["https"] is _PublicHTTPSConnectionPool
        assert second_classes["https"] is _PrivateHTTPSConnectionPool
    finally:
        first.close()
        second.close()
        ordinary.close()


def test_transport_resolves_policy_from_legacy_module_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _PublicHTTPSConnection("example.test", timeout=1.0)
    monkeypatch.setattr(http, "_blocked_host", lambda _: True)
    with pytest.raises(ValueError, match="private or cloud-metadata"):
        connection._new_conn()


def test_socket_deadline_uses_legacy_clock_patch_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http, "time", SimpleNamespace(monotonic=lambda: 100.0))
    guard = _SocketDeadline(SimpleNamespace(sock=None), deadline=110.0)
    try:
        assert guard.remaining() == 10.0
    finally:
        guard.finish()
