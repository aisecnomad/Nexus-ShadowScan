"""Secret-keyed credential pseudonyms; keys never enter reportable configuration."""

from __future__ import annotations

import contextvars
import hmac
import secrets

_DOMAIN = b"shadowscan.credential-identity.v1\0"
_FALLBACK_KEY = secrets.token_bytes(32)
# The active key, and whether it is the operator's stable key.
_identity_key: contextvars.ContextVar[tuple[bytes, bool] | None] = contextvars.ContextVar(
    "shadowscan_credential_identity_key", default=None
)


def set_credential_identity_key(
    key: bytes, *, stable: bool = False
) -> contextvars.Token[tuple[bytes, bool] | None]:
    """Use a scan's private key in this worker; restore the token on every exit.

    ``stable`` marks the operator's ``SHADOWSCAN_IDENTITY_KEY``: values keyed
    with it stay equal between the scans that use it.
    """
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("credential identity key must contain at least 32 secret bytes")
    return _identity_key.set((key, stable))


def reset_credential_identity_key(token: contextvars.Token[tuple[bytes, bool] | None]) -> None:
    _identity_key.reset(token)


def credential_identity_scope() -> str:
    """``keyed`` under the operator's stable key, else ``run``: digests made now are scan-local."""
    active = _identity_key.get()
    return "keyed" if active is not None and active[1] else "run"


def keyed_credential_digest(value: str) -> str:
    """A domain-separated HMAC, with process-local privacy for direct library calls.

    Engine workers supply one scan-wide random key, or the operator's stable
    key. Calls outside an Engine use an ephemeral process key; it is never
    exported and does not establish comparability between processes.
    """
    active = _identity_key.get()
    key = active[0] if active is not None else _FALLBACK_KEY
    return hmac.digest(key, _DOMAIN + value.encode("utf-8"), "sha256").hex()
