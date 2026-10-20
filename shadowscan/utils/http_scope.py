"""The HTTP policy of the current connector worker, importable without the HTTP transport.

The engine sets the private-origin policy and the request deadline around every
connector, local ones included, and resets them afterwards. Keeping the context
variables here lets a run that opens no connection, such as a local code scan or
a pre-commit check, skip importing ``requests`` and ``urllib3``.
:mod:`shadowscan.utils.http` imports these same objects, so a client created by
a connector that loads the transport later still reads the policy the engine
set: there is exactly one policy, never a copy that a client could miss.
"""

from __future__ import annotations

import contextvars
import threading

_allow_private_origin: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "shadowscan_allow_private_origin", default=False
)
# (monotonic deadline, cancellation event) of the connector the current worker runs.
_request_limits: contextvars.ContextVar[tuple[float | None, threading.Event | None]] = contextvars.ContextVar(
    "shadowscan_request_limits", default=(None, None)
)


def set_allow_private_origin(enabled: bool) -> contextvars.Token[bool]:
    """Set the current worker's policy; callers must reset the returned token."""
    if not isinstance(enabled, bool):
        raise TypeError("allow_private_origin must be a boolean")
    return _allow_private_origin.set(enabled)


def reset_allow_private_origin(token: contextvars.Token[bool]) -> None:
    """Restore the policy after a connector finishes, including failed scans."""
    _allow_private_origin.reset(token)


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
