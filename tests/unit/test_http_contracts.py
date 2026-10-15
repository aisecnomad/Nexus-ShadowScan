"""Tripwires for urllib3 internals used by the destination-enforcing transport."""

from __future__ import annotations

import inspect

from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.response import HTTPResponse

from shadowscan.utils.http import (
    _AcquisitionHTTPSConnectionPool,
    _DestinationPolicyAdapter,
    _PrivateHTTPSConnection,
    _PrivateHTTPSConnectionPool,
    _PublicHTTPSConnection,
    _PublicHTTPSConnectionPool,
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
    # allow_private_origin lifts only the address check: the private class keeps
    # the public numeric connect and urllib3's TLS hostname verification.
    assert {name for name in vars(_PrivateHTTPSConnection) if not name.startswith("__")} == {
        "allow_private_origin"
    }


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
