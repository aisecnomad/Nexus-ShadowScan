"""Small, domain-separated key derivation using only the standard library."""

from __future__ import annotations

import hashlib
import hmac


def hkdf_sha256(key: bytes, *, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF-SHA256 extract and expand; an omitted salt is all zeros."""
    size = hashlib.sha256().digest_size
    if not 0 < length <= 255 * size:
        raise ValueError("invalid derived key length")
    extracted = hmac.digest(salt or bytes(size), key, "sha256")
    output = bytearray()
    block = b""
    for counter in range(1, (length + size - 1) // size + 1):
        block = hmac.digest(extracted, block + info + bytes([counter]), "sha256")
        output.extend(block)
    return bytes(output[:length])


def plugin_identity_key(run_key: bytes, plugin_id: str, ordinal: int) -> bytes:
    """Derive a private key for one configured plugin, not its siblings."""
    # Length-prefix the UTF-8 ID; the remaining decimal ordinal is a separate
    # field, so IDs ending in digits cannot collide with another job's context.
    identifier = plugin_id.encode("utf-8")
    if ordinal < 1:
        raise ValueError("invalid plugin configuration ordinal")
    info = (
        b"shadowscan-plugin:" + len(identifier).to_bytes(8, "big") + identifier + str(ordinal).encode("ascii")
    )
    return hkdf_sha256(run_key, info=info)
