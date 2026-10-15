"""Read-only bounded format inventory; never load tensors, modules or external data.

Format evidence describes an artifact, not a working model or an active agent.
The reader seeks across payloads and bounds cumulative metadata bytes and fields.
GGUF array values (tokenizer vocabularies, scores, merges) are skipped without
being materialised, under their own element and byte bounds.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, BinaryIO

from shadowscan.utils.files import changed_since, open_confined_file
from shadowscan.utils.safe_json import strict_json_loads

DEFAULT_METADATA_BYTES = 64 * 1024
MAX_FIELDS = 8192
MAX_TENSORS = 2048
# GGUF arrays are skipped, not parsed into fields: fixed-size items by seeking,
# strings by walking their length prefixes in bounded chunks. These bounds
# apply per file; the bytes read while skipping are also reported to the
# caller's ``skip_charge``.
MAX_ARRAY_ELEMENTS = 8 * 1024 * 1024
MAX_ARRAY_SKIP_BYTES = 64 * 1024 * 1024
_SKIP_CHUNK = 64 * 1024
_GGUF_SCALARS = {
    0: "<B",
    1: "<b",
    2: "<H",
    3: "<h",
    4: "<I",
    5: "<i",
    6: "<f",
    7: "<?",
    10: "<Q",
    11: "<q",
    12: "<d",
}
PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
ARTIFACT_SUFFIXES = frozenset({".gguf", ".safetensors", ".onnx", ".exe", ".bin", ".pkg"})
# ELF, PE (MZ) and Mach-O (32/64-bit, both byte orders, universal) headers. An
# extensionless file is searched for a PyInstaller cookie only when it starts
# with one of them, so ordinary text costs its four-byte prefix, not a tail.
_EXECUTABLE_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


class ArtifactBudgetExhausted(ValueError):
    """The caller's scan-wide artifact byte budget cannot cover a read.

    Callers raise it from ``charge`` and may then analyse the file another
    way: it says nothing about the file itself.
    """


@dataclass
class ArtifactInspection:
    format: str
    metadata: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(
        default_factory=lambda: [
            "Format inventory does not establish usable model weights, execution, or agency.",
            "Tensor data, embedded code, and external paths were not loaded or executed.",
        ]
    )


class _Reader:
    def __init__(
        self,
        stream: BinaryIO,
        size: int,
        budget: int,
        check: Callable[[], None],
        charge: Callable[[int], None],
        skip_charge: Callable[[int], None],
    ) -> None:
        self.stream, self.size, self.remaining, self.check = stream, size, budget, check
        self.fields = 0
        self.charge = charge
        self.skip_charge = skip_charge
        self.elements = 0
        self.skimmed = 0

    def read(self, size: int) -> bytes:
        self.check()
        if size < 0 or size > self.remaining:
            raise ValueError("artifact metadata byte limit exceeded")
        if self.stream.tell() + size > self.size:
            raise ValueError("truncated artifact metadata")
        self.charge(size)
        self.remaining -= size
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError("artifact changed or truncated while reading")
        return data

    def unpack(self, fmt: str) -> tuple[Any, ...]:
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))

    def seek(self, offset: int) -> None:
        self.check()
        if not 0 <= offset <= self.size:
            raise ValueError("artifact offset outside file")
        self.stream.seek(offset)

    def field(self) -> None:
        self.check()
        self.fields += 1
        if self.fields > MAX_FIELDS:
            raise ValueError("artifact metadata field limit exceeded")

    def array_elements(self, count: int) -> None:
        self.check()
        self.elements += count
        if self.elements > MAX_ARRAY_ELEMENTS:
            raise ValueError("artifact array element limit exceeded")

    def skim(self, size: int) -> bytes:
        """Read bytes only to find the end of an array; they are never retained or reported."""
        self.check()
        if size < 0 or self.skimmed + size > MAX_ARRAY_SKIP_BYTES:
            raise ValueError("artifact array byte limit exceeded")
        self.skip_charge(size)
        self.skimmed += size
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError("artifact changed or truncated while reading")
        return data


def _gguf_string(reader: _Reader) -> bytes:
    length = reader.unpack("<Q")[0]
    return reader.read(length)


def _gguf_value(reader: _Reader, kind: int) -> int | None:
    reader.field()
    if kind in _GGUF_SCALARS:
        value = reader.unpack(_GGUF_SCALARS[kind])[0]
        return value if type(value) is int else None
    if kind == 8:
        _gguf_string(reader).decode("utf-8")
        return None
    if kind == 9:
        item_type, count = reader.unpack("<IQ")
        _gguf_skip_array(reader, item_type, count, 1)
        return None
    raise ValueError("unsupported GGUF metadata type")


def _gguf_skip_array(reader: _Reader, item_type: int, count: int, depth: int) -> None:
    """Move past an array's values without materialising them.

    A llama.cpp vocabulary holds 32K-256K strings, far more than the field
    limit, so values are not fields: fixed-size items are skipped by seeking
    and strings by their length prefixes, under the element and skim bounds.
    String contents are not decoded or validated.
    """
    if depth > 8:
        raise ValueError("GGUF metadata nesting limit exceeded")
    reader.array_elements(count)
    if item_type in _GGUF_SCALARS:
        reader.seek(reader.stream.tell() + count * struct.calcsize(_GGUF_SCALARS[item_type]))
    elif item_type == 8:
        _gguf_skip_strings(reader, count)
    elif item_type == 9:
        for _ in range(count):
            nested_type, nested_count = struct.unpack("<IQ", reader.skim(12))
            _gguf_skip_array(reader, nested_type, nested_count, depth + 1)
    else:
        raise ValueError("unsupported GGUF metadata type")


def _gguf_skip_strings(reader: _Reader, count: int) -> None:
    """Walk ``count`` length-prefixed strings, reading bounded chunks; seek past the last."""
    position = reader.stream.tell()
    base, chunk = position, b""
    for number in range(count):
        if not number % 4096:
            reader.check()
        if position + 8 > reader.size:
            raise ValueError("truncated artifact metadata")
        if position + 8 > base + len(chunk):
            reader.seek(position)
            base, chunk = position, reader.skim(min(_SKIP_CHUNK, reader.size - position))
        position += 8 + struct.unpack_from("<Q", chunk, position - base)[0]
    if position > reader.size:
        raise ValueError("truncated artifact metadata")
    reader.seek(position)


def _gguf(reader: _Reader) -> ArtifactInspection:
    reader.seek(0)
    magic, version, tensors, entries = reader.unpack("<4sIQQ")
    if magic != b"GGUF" or version not in {2, 3}:
        raise ValueError("unsupported or invalid GGUF header")
    if tensors > MAX_TENSORS or entries > MAX_FIELDS:
        raise ValueError("GGUF header count limit exceeded")
    alignment = 32
    keys: set[bytes] = set()
    for _ in range(entries):
        key = _gguf_string(reader)
        key.decode("utf-8")
        if key in keys:
            raise ValueError("duplicate GGUF metadata key")
        keys.add(key)
        kind = reader.unpack("<I")[0]
        value = _gguf_value(reader, kind)
        if key == b"general.alignment":
            if kind != 4 or value is None or not 1 <= value <= 65536 or value & (value - 1):
                raise ValueError("invalid GGUF alignment")
            alignment = value
    offsets: list[int] = []
    for _ in range(tensors):
        reader.field()
        _gguf_string(reader).decode("utf-8")
        dimensions = reader.unpack("<I")[0]
        if not 1 <= dimensions <= 4:
            raise ValueError("invalid GGUF tensor dimensions")
        if any(reader.unpack("<Q")[0] == 0 for _ in range(dimensions)):
            raise ValueError("invalid GGUF tensor shape")
        reader.unpack("<I")  # ggml type is inventoried, not loaded or interpreted.
        offsets.append(reader.unpack("<Q")[0])
    payload_start = (reader.stream.tell() + alignment - 1) // alignment * alignment
    if tensors and (
        payload_start > reader.size or any(x >= reader.size - payload_start or x % alignment for x in offsets)
    ):
        raise ValueError("GGUF tensor offset outside file or alignment")
    return ArtifactInspection(
        "gguf",
        {
            "version": version,
            "tensor_count": tensors,
            "metadata_count": entries,
            "validation": "bounded-header-only",
        },
    )


_DTYPE_BITS = {
    "BOOL": 8,
    "U8": 8,
    "I8": 8,
    "U16": 16,
    "I16": 16,
    "U32": 32,
    "I32": 32,
    "U64": 64,
    "I64": 64,
    "F16": 16,
    "BF16": 16,
    "F32": 32,
    "F64": 64,
    "F8_E4M3": 8,
    "F8_E5M2": 8,
    "F8_E8M0": 8,
}


def _safetensors(reader: _Reader) -> ArtifactInspection:
    reader.seek(0)
    length = reader.unpack("<Q")[0]
    if length < 2:
        raise ValueError("invalid safetensors header length")
    header = reader.read(length)
    if not header.startswith(b"{"):
        raise ValueError("safetensors header must begin with an object")
    document = strict_json_loads(header.decode("utf-8"))
    if not isinstance(document, dict) or len(document) > MAX_TENSORS + 1:
        raise ValueError("invalid safetensors header or tensor limit exceeded")
    data_size = reader.size - 8 - length
    offsets: list[tuple[int, int]] = []
    for name, item in document.items():
        reader.field()
        if name == "__metadata__":
            if not isinstance(item, dict) or any(not isinstance(v, str) for v in item.values()):
                raise ValueError("invalid safetensors metadata")
            continue
        if not isinstance(item, dict) or set(item) != {"dtype", "shape", "data_offsets"}:
            raise ValueError("invalid safetensors tensor descriptor")
        shape, interval = item["shape"], item["data_offsets"]
        if not isinstance(shape, list) or len(shape) > 64 or any(type(n) is not int or n < 0 for n in shape):
            raise ValueError("invalid safetensors tensor shape")
        if not isinstance(interval, list) or len(interval) != 2 or any(type(n) is not int for n in interval):
            raise ValueError("invalid safetensors data offsets")
        begin, end = interval
        if not 0 <= begin <= end <= data_size:
            raise ValueError("safetensors data offsets outside payload")
        dtype = item["dtype"]
        if not isinstance(dtype, str) or dtype not in _DTYPE_BITS:
            raise ValueError("unsupported safetensors dtype")
        elements = 1
        for extent in shape:
            elements *= extent
            if elements > 2**63:
                raise ValueError("safetensors tensor size limit exceeded")
        if (elements * _DTYPE_BITS[dtype] + 7) // 8 != end - begin:
            raise ValueError("safetensors tensor shape and offsets disagree")
        offsets.append((begin, end))
    covered = 0
    for begin, end in sorted(offsets):
        if begin != covered:
            raise ValueError("safetensors payload overlaps or contains holes")
        covered = end
    if covered != data_size:
        raise ValueError("safetensors unindexed payload")
    return ArtifactInspection(
        "safetensors",
        {"tensor_count": len(offsets), "header_bytes": length, "validation": "bounded-header-and-offsets"},
    )


def _varint(reader: _Reader, end: int) -> int:
    value = 0
    for number in range(10):
        if reader.stream.tell() >= end:
            raise ValueError("truncated protobuf varint")
        byte = reader.read(1)[0]
        if number == 9 and byte > 1:
            raise ValueError("protobuf varint overflow")
        value |= (byte & 127) << (7 * number)
        if byte < 128:
            return value
    raise ValueError("invalid protobuf varint")


def _protobuf_fields(reader: _Reader, end: int) -> list[tuple[int, int, int, int]]:
    fields = []
    while reader.stream.tell() < end:
        reader.field()
        key = _varint(reader, end)
        number, wire = key >> 3, key & 7
        if number == 0 or number >= 2**29:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value = _varint(reader, end)
            fields.append((number, wire, value, 0))
            continue
        if wire == 2:
            length = _varint(reader, end)
        elif wire in {1, 5}:
            length = 8 if wire == 1 else 4
        else:
            raise ValueError("unsupported protobuf wire type")
        start = reader.stream.tell()
        if start + length > end:
            raise ValueError("protobuf field outside message")
        fields.append((number, wire, start, length))
        reader.seek(start + length)
    return fields


def _onnx(reader: _Reader) -> ArtifactInspection:
    reader.seek(0)
    fields = _protobuf_fields(reader, reader.size)
    versions = [value for number, wire, value, _ in fields if number == 1 and wire == 0]
    graphs = [(start, length) for number, wire, start, length in fields if number == 7 and wire == 2]
    if len(versions) != 1 or not 1 <= versions[0] <= 13 or len(graphs) != 1:
        raise ValueError("unverified ONNX model metadata or unsupported IR version")
    start, length = graphs[0]
    reader.seek(start)
    graph = _protobuf_fields(reader, start + length)
    if not any(number == 2 and wire == 2 for number, wire, _, _ in graph):
        raise ValueError("ONNX graph name field missing")
    imports = sum(number == 8 and wire == 2 for number, wire, _, _ in fields)
    if versions[0] >= 3 and not imports:
        raise ValueError("ONNX opset import missing")
    return ArtifactInspection(
        "onnx",
        {
            "ir_version": versions[0],
            "opset_import_count": imports,
            "node_count": sum(n == 1 and w == 2 for n, w, _, _ in graph),
            "validation": "protobuf-envelope-only",
        },
        [
            "ONNX has no unique magic header; matching protobuf fields are candidate format evidence.",
            "Operator semantics, tensor data and external-data paths were not validated or accessed.",
            "Artifact presence does not establish execution or agency.",
        ],
    )


def _pyinstaller(reader: _Reader) -> ArtifactInspection | None:
    # Bound tail search; embedded signatures deeper than this remain outside scope.
    tail_size = min(reader.size, reader.remaining // 2)
    reader.seek(reader.size - tail_size)
    tail = reader.read(tail_size)
    index = tail.rfind(PYINSTALLER_MAGIC)
    if index < 0:
        return None
    cookie_start = reader.size - tail_size + index
    available = tail[index:]
    if len(available) < 24:
        raise ValueError("truncated PyInstaller archive cookie")
    _, package_size, toc_offset, toc_size, python_version = struct.unpack("!8sIIII", available[:24])
    # Modern cookie has a 64-byte library field. Python 3 cookies use it;
    # legacy 2.x cookies (24 bytes) are deliberately unsupported.
    if len(available) < 88 or not 300 <= python_version <= 399:
        raise ValueError("unsupported PyInstaller cookie version")
    archive_end = cookie_start + 88
    archive_start = archive_end - package_size
    if archive_start < 0 or package_size < 88 or toc_offset + toc_size > package_size - 88:
        raise ValueError("PyInstaller archive offsets outside file")
    reader.seek(archive_start + toc_offset)
    toc = reader.read(toc_size)
    position, entries = 0, 0
    while position < len(toc):
        reader.field()
        if len(toc) - position < 18:
            raise ValueError("truncated PyInstaller TOC")
        length, offset, packed, _unpacked, compressed, _kind = struct.unpack(
            "!iIIIBc", toc[position : position + 18]
        )
        if (
            length < 19
            or position + length > len(toc)
            or offset + packed > toc_offset
            or compressed not in {0, 1}
        ):
            raise ValueError("invalid PyInstaller TOC entry")
        if b"\x00" not in toc[position + 18 : position + length]:
            raise ValueError("unterminated PyInstaller TOC name")
        position += length
        entries += 1
    return ArtifactInspection(
        "pyinstaller",
        {"entry_count": entries, "python_version": python_version, "validation": "bounded-cookie-and-toc"},
        [
            "PyInstaller packaging does not establish AI functionality or agency.",
            "Embedded code was not extracted, decompressed, imported, or executed.",
            "Cookie search is confined to the bounded file tail; legacy cookies are unsupported.",
        ],
    )


def inspect_artifact(
    path: PurePath,
    *,
    dir_fd: int | None = None,
    max_bytes: int = DEFAULT_METADATA_BYTES,
    check: Callable[[], None] = lambda: None,
    charge: Callable[[int], None] = lambda size: None,
    skip_charge: Callable[[int], None] = lambda size: None,
) -> ArtifactInspection | None:
    """Inspect the selected regular file through one confined, identity-checked handle.

    ``charge`` receives metadata bytes before they are read and
    ``skip_charge`` the bytes read only to skip GGUF array values; either may
    raise to stop the inspection.
    """
    if type(max_bytes) is not int or max_bytes < 128:
        raise ValueError("artifact metadata byte limit must be at least 128")
    with open_confined_file(path, label="model artifact", dir_fd=dir_fd) as (stream, before):
        reader = _Reader(stream, before.st_size, max_bytes, check, charge, skip_charge)
        suffix = path.suffix.lower()
        result: ArtifactInspection | None
        prefix = reader.read(min(4, before.st_size))
        if suffix == ".gguf" or prefix == b"GGUF":
            result = _gguf(reader)
        elif suffix == ".safetensors":
            result = _safetensors(reader)
        elif suffix == ".onnx":
            result = _onnx(reader)
        elif suffix in ARTIFACT_SUFFIXES or prefix.startswith(_EXECUTABLE_MAGIC):
            result = _pyinstaller(reader)
        else:
            result = None
        if changed_since(before, stream.fileno()):
            raise ValueError("artifact changed while reading")
        if result is not None:
            result.metadata["bytes_read"] = max_bytes - reader.remaining
            if reader.elements:
                result.metadata["array_bytes_skimmed"] = reader.skimmed
                result.limitations.append(
                    "Array values (tokenizer vocabularies, scores, merges) were skipped without validation."
                )
        return result
