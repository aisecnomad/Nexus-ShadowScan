"""Small, domain-separated key derivation using only the standard library."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

MAX_IDENTITY_MATERIAL_BYTES = 1024 * 1024
MAX_IDENTITY_MATERIAL_ENTRIES = 4096


@dataclass(repr=False)
class _IdentityMaterial:
    key: bytes
    entries: dict[str, bytes] = field(default_factory=dict)
    size: int = 0


_identity_material: ContextVar[_IdentityMaterial | None] = ContextVar(
    "shadowscan_plugin_identity_material", default=None
)


@contextmanager
def capture_identity_material(key: bytes) -> Iterator[dict[str, bytes]]:
    """Capture bounded preimages only for a worker's private, in-memory IPC."""
    material = _IdentityMaterial(key)
    token = _identity_material.set(material)
    try:
        yield material.entries
    finally:
        _identity_material.reset(token)


def identity_hmac_digest(key: bytes, message: bytes) -> bytes:
    """Unchanged SHA-256 HMAC, with optional ephemeral process rekey material."""
    digest = hmac.digest(key, message, "sha256")
    material = _identity_material.get()
    if material is not None and hmac.compare_digest(key, material.key):
        _remember_identity(material, digest.hex(), message)
    return digest


def finding_identity_digest(message: bytes) -> str:
    """Existing finding-ID hash, optionally recording its raw ephemeral input."""
    identifier = "ss-" + hashlib.sha256(message).hexdigest()[:16]
    material = _identity_material.get()
    if material is not None:
        _remember_identity(material, identifier, message)
    return identifier


def _remember_identity(material: _IdentityMaterial, identifier: str, message: bytes) -> None:
    if identifier in material.entries:
        if material.entries[identifier] != message:
            raise ValueError("plugin identity material collision")
    else:
        size = material.size + len(message) + len(identifier)
        if size > MAX_IDENTITY_MATERIAL_BYTES or len(material.entries) >= MAX_IDENTITY_MATERIAL_ENTRIES:
            raise ValueError("plugin identity material exceeds transport limit")
        material.entries[identifier] = message
        material.size = size


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
