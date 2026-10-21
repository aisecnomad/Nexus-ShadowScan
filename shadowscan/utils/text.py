"""Text helpers: redaction, safe file reading and small parsers."""

from __future__ import annotations

import base64
import codecs
import io
import json
import math
import re
import tokenize
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from shadowscan.utils.files import NotRegularFileError, open_confined_file
from shadowscan.utils.redaction import credential_id
from shadowscan.utils.safe_json import strict_json_loads

_BINARY_SNIFF = 8192
# Reported by ``read_text`` for a NUL-bearing file that is not text in any
# encoding it decodes and not a binary artifact it may skip (``_skips_binary``).
# Callers pass only files they would analyze, so this is a coverage gap, never
# a reason to treat the scan as complete.
BINARY_CONTENT_ERROR = "binary or undecodable content in analyzable file"
# Notes ``read_text`` adds for text it read although it was not clean UTF-8. The file is analyzed in
# full, so these leave coverage complete; they only tell the operator what the reader did.
STRAY_NUL_NOTE = "stray NUL bytes in text, read as text"
INVALID_UTF8_NOTE = "not valid UTF-8, the bytes that are not were replaced"
# A file is text with stray NUL bytes, not binary, when it is valid UTF-8, holds no other control
# character in the sniff window, and at most one byte in ``_SPARSE_NUL_RATIO`` is NUL. Below
# ``_STRAY_NUL_MIN_BYTES`` one NUL is too large a share of the file to call it stray. Compressed or
# encrypted data is about 0.4% NUL, but it is not valid UTF-8.
_SPARSE_NUL_RATIO = 200
_STRAY_NUL_MIN_BYTES = 512
_BINARY_CONTROLS = frozenset(range(0x20)) - {0x00, 0x09, 0x0A, 0x0C, 0x0D}
# Byte-order marks, longest first (the UTF-32LE mark begins with the UTF-16LE one).
_BOM_CODECS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
)
# Headers of compiled, packed and media artifacts. An interpreter can still run
# a script whose first line looks like a header, so this evidence alone never
# hides a name the scanner analyzes by its extension (``.sh``, ``.js``); see
# ``_skips_binary`` for where it does apply.
_BINARY_MAGIC: tuple[bytes, ...] = (
    b"\x7fELF",  # ELF
    b"\xca\xfe\xba\xbe",  # Mach-O universal
    b"\xfe\xed\xfa\xce",  # Mach-O
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"MZ",  # PE and DOS executables
    b"\x00asm",  # WebAssembly
    b"\x1f\x8b",  # gzip
    b"PK\x03\x04",  # zip, jar, wheel
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"\x28\xb5\x2f\xfd",  # zstd
    b"7z\xbc\xaf\x27\x1c",  # 7z
    b"SQLite format 3\x00",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
    b"OggS\x00",  # Ogg (Vorbis, Opus, Theora), stream structure version 0
    b"ID3",  # MP3 with an ID3v2 tag
    b"fLaC",  # FLAC
    b"\x1a\x45\xdf\xa3",  # Matroska and WebM
    b"\x00\x00\x01\x00",  # ICO
    b"\x00\x00\x02\x00",  # CUR
    b"II*\x00",  # TIFF, little-endian
    b"MM\x00*",  # TIFF, big-endian
    b"8BPS",  # Photoshop
    b"wOFF",  # WOFF font
    b"wOF2",  # WOFF2 font
    b"OTTO",  # OpenType (CFF) font
    b"\x00\x01\x00\x00",  # TrueType font
    b"ttcf",  # TrueType collection
)
# Containers whose type is named after a fixed header field rather than at the
# start: RIFF names its form at offset 8, an ISO base media file (MP4, MOV,
# M4A, HEIC, AVIF) its first box type, ``ftyp``, at offset 4.
_RIFF_FORMS = frozenset({b"WEBP", b"WAVE", b"AVI "})
# Text codec that a PEP 263 coding cookie must not select: its decoder is not
# linear in its input (``punycode`` re-copies its output for every code point,
# about 30 s for a 1 MB file with the GIL held), so a hostile cookie would stall
# the scan. Such a file is reported as undecodable instead.
_SLOW_SOURCE_CODECS = frozenset({"punycode"})
# Printable ASCII, the tab and the line breaks: a cookie's line is ASCII, and a
# declared codec must read these bytes as themselves. UTF-16 and UTF-32 without
# a byte-order mark, UTF-7, HZ and EBCDIC code pages read an ASCII source as
# other characters (CJK text for UTF-16), which would be analyzed as garbage
# without a gap; CPython refuses most of them with "encoding problem".
_ASCII_SOURCE = bytes(range(0x20, 0x7F)) + b"\t\n\r"
# Epoch seconds or milliseconds, optionally fractional (nginx $msec, Kong).
_EPOCH_RX = re.compile(r"\d{1,19}(?:\.\d{1,9})?")
# A compact calendar day (yyyymmdd); checked before the epoch form claims it.
_CALENDAR_DAY_RX = re.compile(r"(?:19|20)\d{6}")


def redact(value: str, keep: int = 4) -> str:
    """Return a keyed credential pseudonym without retaining raw fragments.

    ``keep`` remains accepted for compatibility with older call sites, but no
    prefix or suffix is kept. Engine scans share one private key; callers
    wanting stability between scans supply SHADOWSCAN_IDENTITY_KEY. New code
    should call ``credential_id`` directly.
    """
    del keep
    if not value:
        return value
    return credential_id(value)


def _skips_binary(name: str, raw: bytes, analyzable_name: bool) -> bool:
    """Whether NUL-bearing ``raw`` is a recognised binary artifact to skip without a coverage gap.

    The content must start with a recognised header (``_binary_header``). Even then a name
    analyzed for its own sake stays a gap unless it has no extension at all.
    Packet-like ``.ts`` bytes cannot establish that the file is video rather
    than TypeScript: source comments can contain the same binary padding.
    Unrecognised binary content is always a gap.
    """
    if not _binary_header(raw):
        return False
    return not analyzable_name or "." not in name


def _binary_header(raw: bytes) -> bool:
    """Whether ``raw`` starts with the header of a compiled, packed or media artifact."""
    return (
        raw.startswith(_BINARY_MAGIC)
        or (raw[:4] == b"RIFF" and raw[8:12] in _RIFF_FORMS)
        or raw[4:8] == b"ftyp"
    )


# CPython's PEP 263 cookie pattern. The second source line carries the cookie
# only when the first is blank or a comment, as the interpreter reads it.
_CODING_COOKIE = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_BLANK_SOURCE_LINE = re.compile(r"^[ \t\f]*(?:[#\r\n]|$)")


def _declared_source_cookie(raw: bytes) -> str | None:
    """The PEP 263 cookie the first two lines declare, or None."""
    for index, line in enumerate(raw.split(b"\n", 2)[:2]):
        text = line.decode("latin-1")
        match = _CODING_COOKIE.match(text)
        if match is not None:
            return match.group(1)
        if index == 0 and _BLANK_SOURCE_LINE.match(text) is None:
            return None
    return None


def _refused_cookie_result(raw: bytes) -> str | None:
    """What a cookie ``tokenize.detect_encoding`` itself refused means for the caller.

    The refusal set grows with the interpreter: Python 3.14 refuses
    ``punycode`` and UTF-32 cookies that 3.13 still honors. The scanned estate
    may run an interpreter that honors such a cookie, so a refused cookie
    naming a slow codec or one that does not read ASCII as ASCII stays a
    coverage gap on every interpreter, never silently analyzed with the
    default decoding. Any other refusal (a BOM that contradicts the cookie, a
    codec no interpreter honors as a source encoding) keeps the caller's
    default decoding, as before.
    """
    cookie = _declared_source_cookie(raw)
    if cookie is None:
        return None
    try:
        codec = codecs.lookup(cookie).name
        if codec in _SLOW_SOURCE_CODECS:
            raise ValueError(BINARY_CONTENT_ERROR)
        if _ASCII_SOURCE.decode(cookie) != _ASCII_SOURCE.decode("ascii"):
            raise ValueError(BINARY_CONTENT_ERROR)
    except LookupError:
        return None
    except UnicodeError:
        raise ValueError(BINARY_CONTENT_ERROR) from None
    return None


def _python_source_text(raw: bytes) -> str | None:
    """Decode a Python source with the PEP 263 codec it declares; None when it declares none.

    A cookie naming UTF-8, an unknown codec or a codec that is not a text
    encoding leaves the caller's default decoding in place (the interpreter
    cannot run such a file either). A text codec that cannot decode the bytes,
    that does not read ASCII as ASCII (see ``_ASCII_SOURCE``), or that is too
    slow to run on untrusted input, is a coverage gap — including when the
    running interpreter's ``detect_encoding`` refuses the cookie itself (see
    ``_refused_cookie_result``), because the scanned estate's interpreter may
    still honor it.
    """
    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        codec = codecs.lookup(declared).name
    except LookupError:
        return None
    except SyntaxError:
        return _refused_cookie_result(raw)  # a gap, or the default decoding
    if codec == "utf-8":
        return None
    if codec in _SLOW_SOURCE_CODECS:
        raise ValueError(BINARY_CONTENT_ERROR)
    try:
        if _ASCII_SOURCE.decode(declared) != _ASCII_SOURCE.decode("ascii"):
            raise ValueError(BINARY_CONTENT_ERROR)
        return raw.decode(declared)
    except LookupError:
        return None
    except UnicodeError:
        # Name the gap, not the position or byte the decoder rejected.
        raise ValueError(BINARY_CONTENT_ERROR) from None


def _stray_nul_text(raw: bytes) -> str | None:
    """The text of a file that holds a few NUL bytes (a TypeScript cache-key separator), or None.

    A NUL in the sniff window used to make the whole file a coverage gap, whatever else it held, so
    the source around it was never analyzed. Binary data fails at least one of the tests below (it is
    not valid UTF-8, it holds other control characters, or it is far more than 0.5% NUL), so it stays
    a gap. The NUL bytes stay in the text returned: bash drops them from a script, but Node and PHP keep
    them, so what they mean is for the caller to decide.
    """
    if len(raw) < _STRAY_NUL_MIN_BYTES or raw.count(b"\x00") * _SPARSE_NUL_RATIO > len(raw):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(character) in _BINARY_CONTROLS for character in text[:_BINARY_SNIFF]):
        return None
    return text


# The share of replacement characters in any bounded window above which "text that is not UTF-8" is
# no longer text (random or compressed bytes are over half invalid; Latin-1 prose is a few percent).
_MAX_REPLACED_SHARE = 0.10
_REPLACED_ALLOWANCE = (
    4  # a short file with a few bad bytes is text; the share rule needs room to mean anything
)


def _decode_utf8(raw: bytes, notes: list[str] | None, codec: str = "utf-8", *, strict: bool = False) -> str:
    """Decode UTF-8, replacing the bytes that are not when the content is text, and say so in ``notes``.

    ASCII-compatible text in another encoding (Latin-1 or Windows-1252 prose) reads the same here for
    every pattern the scanner looks for, so skipping the file as a coverage gap lost everything the
    scanner would have found and hid nothing. Content that is mostly not valid UTF-8, or that holds
    control characters other than tab, line breaks and form feed anywhere, is not that: it
    stays a gap, as do EBCDIC and other encodings that write ASCII differently. ``strict`` keeps the
    gap for the files whose own runtime rejects bytes that are not valid UTF-8 and whose only other
    encodings are declared (Python sources and notebooks).
    """
    try:
        return raw.decode(codec)
    except UnicodeDecodeError:
        if strict:
            raise
        text = raw.decode(codec, errors="replace")
        # Check the entire bounded input. An ordinary-text prefix must not
        # conceal a binary body after the first sniff window.
        for offset in range(0, len(text), _BINARY_SNIFF):
            window = text[offset : offset + _BINARY_SNIFF]
            if window.count("\ufffd") > max(_REPLACED_ALLOWANCE, _MAX_REPLACED_SHARE * len(window)) or any(
                ord(character) in _BINARY_CONTROLS for character in window
            ):
                raise
        if notes is not None:
            notes.append(INVALID_UTF8_NOTE)
        return text


def _decode_text(raw: bytes, name: str, analyzable_name: bool, notes: list[str] | None = None) -> str | None:
    """Decode file content for analysis; None for a recognised binary artifact (``_skips_binary``)."""
    for bom, codec in _BOM_CODECS:
        if raw.startswith(bom):
            decoded = (
                _decode_utf8(raw, notes, codec, strict=name.lower().endswith((".py", ".ipynb")))
                if codec == "utf-8-sig"
                else raw.decode(codec)
            )
            # A mark does not make the rest text: a NUL in the decoded prefix
            # is still binary content under an analyzable name.
            if "\x00" in decoded[:_BINARY_SNIFF]:
                raise ValueError(BINARY_CONTENT_ERROR)
            return decoded
    if b"\x00" in raw[:_BINARY_SNIFF]:
        if _skips_binary(name, raw, analyzable_name):
            return None
        stray = _stray_nul_text(raw)
        if stray is None:
            raise ValueError(BINARY_CONTENT_ERROR)
        if notes is not None:
            notes.append(STRAY_NUL_NOTE)
        return stray
    if name.lower().endswith(".py"):
        declared = _python_source_text(raw)
        if declared is not None:
            return declared
    return _decode_utf8(raw, notes, strict=name.lower().endswith((".py", ".ipynb")))


def read_text(
    path: PurePath,
    max_bytes: int,
    errors: list[str] | None = None,
    *,
    dir_fd: int | None = None,
    analyzable_name: bool = True,
    notes: list[str] | None = None,
) -> str | None:
    """Read a bounded regular file without following a symlink in any path component.

    With ``dir_fd``, ``path`` is relative to that open directory, normally the
    scan root, and only the components below it are opened; otherwise the
    whole absolute path is. Each directory is opened with ``O_NOFOLLOW``
    relative to its parent (:func:`open_confined_file`), so a directory swapped
    for a link between directory traversal and reading fails the read instead
    of redirecting it outside the tree. Validate the opened descriptor, not a
    separate stat result: the file may change between directory traversal and
    reading. Text with a byte-order mark (UTF-8, UTF-16, UTF-32) is decoded and
    the mark removed, and a Python source is decoded with the codec its PEP 263
    cookie declares. Callers pass only files they would analyze, so any other
    content with a NUL byte in its first 8 KiB is reported as
    ``BINARY_CONTENT_ERROR`` rather than ignored. The exceptions are a recognised
    binary artifact (``_skips_binary``) without any file extension or, with
    ``analyzable_name`` False, any recognised artifact: the caller then reads
    the file only because of the directory it is in, such as an image kept
    beside coding-agent rules; and a large text file with a few stray NUL bytes
    (``_stray_nul_text``). Text that is not valid UTF-8 and holds no NUL is read
    with the invalid bytes replaced (``_decode_utf8``). Both are analyzed in full,
    so they are not gaps: ``notes`` receives a short description of each for the
    caller to report. Limits and I/O failures are reported to callers that track
    completeness.
    """
    try:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        with open_confined_file(path, label="file", dir_fd=dir_fd) as (fh, info):
            if info.st_size > max_bytes:
                raise ValueError("file exceeds max_file_size")
            raw = fh.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("file exceeds max_file_size")
        return _decode_text(raw, path.name, analyzable_name, notes)
    except (OSError, ValueError) as exc:
        _read_failure(exc, errors)
        return None


def _read_failure(exc: OSError | ValueError, errors: list[str] | None) -> None:
    """Record why a bounded read failed, without raw file contents or exception messages."""
    if errors is None:
        return
    if isinstance(exc, NotRegularFileError):
        errors.append("not a regular file")
    elif isinstance(exc, UnicodeError):
        errors.append(BINARY_CONTENT_ERROR)
    elif isinstance(exc, ValueError):
        errors.append(str(exc))
    else:
        errors.append("file could not be read")


def read_credential_text(
    path: PurePath, max_bytes: int, errors: list[str] | None = None, *, dir_fd: int | None = None
) -> str | None:
    """A bounded regular file's bytes as Latin-1 text without NUL bytes, for a credential-only read.

    For a binary or undecodable file that ``read_text`` refuses but whose other
    evidence the caller discounts (a test fixture): credentials are ASCII, so
    every key written in the file survives (UTF-16 text only loses its NUL
    halves), and no decoding can fail. The file is opened as ``read_text``
    opens it, confined and without following links; a failure is recorded in
    ``errors`` as ``read_text`` records it.
    """
    try:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        with open_confined_file(path, label="file", dir_fd=dir_fd) as (fh, info):
            if info.st_size > max_bytes:
                raise ValueError("file exceeds max_file_size")
            raw = fh.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("file exceeds max_file_size")
    except (OSError, ValueError) as exc:
        _read_failure(exc, errors)
        return None
    return raw.replace(b"\x00", b"").decode("latin-1")


# Kernel names of Python kernels: ipykernel's (python3), xeus-python's and nb_conda_kernels'.
_PYTHON_KERNEL = re.compile(r"(?:i?python|xpython)[\d.]*|conda-(?:root|env-.+)-py", re.IGNORECASE)


def _kernel_language(metadata: Any) -> str | None:
    """The kernel language notebook ``metadata`` declares, lower-cased (see ``notebook_to_source``)."""
    if not isinstance(metadata, dict):
        return None
    kernelspec, info = metadata.get("kernelspec"), metadata.get("language_info")
    spec: dict[str, Any] = kernelspec if isinstance(kernelspec, dict) else {}
    kernel, declared = spec.get("name"), spec.get("language")
    if isinstance(kernel, str) and _PYTHON_KERNEL.fullmatch(kernel.strip()):
        declared = "python"
    elif not isinstance(declared, str) or not declared.strip():
        declared = info.get("name") if isinstance(info, dict) else None
    if isinstance(declared, str) and declared.strip():
        return declared.strip().lower()
    return None


def notebook_to_source(
    text: str,
    errors: list[str] | None = None,
    *,
    cells: list[str] | None = None,
    language: list[str] | None = None,
    binary: list[str] | None = None,
) -> str:
    """Extract code cells from a Jupyter notebook as a python source blob.

    The cells are joined by line breaks; ``cells``, when given, receives each
    code cell's source in order, so a caller can treat them one at a time.
    ``binary``, when given, receives the base64 image, audio, video and PDF
    strings of the cells' outputs and attachments, in document order (see
    ``notebook_without_binary_data``).
    ``language``, when given, receives the kernel language the notebook's
    metadata declares, lower-cased, if it declares one: ``python`` when
    ``kernelspec.name`` names a Python kernel (Jupyter starts the kernel its
    name selects, whatever ``kernelspec.language`` says), else
    ``kernelspec.language``, else ``language_info.name``.
    """
    try:
        nb = strict_json_loads(text)
    except (ValueError, RecursionError):
        if errors is not None:
            errors.append("notebook contains invalid JSON")
        return ""
    if not isinstance(nb, dict) or not isinstance(nb.get("cells", []), list):
        if errors is not None:
            errors.append("notebook cells must be an array")
        return ""
    if language is not None and (declared := _kernel_language(nb.get("metadata"))) is not None:
        language.append(declared)
    out: list[str] = []
    for cell in nb.get("cells", []):
        if not isinstance(cell, dict):
            if errors is not None:
                errors.append("notebook cell must be an object")
            continue
        if binary is not None:
            binary.extend(_binary_output_data(cell))
        if cell.get("cell_type") != "code":
            continue
        src = cell.get("source", "")
        if isinstance(src, list):
            if not all(isinstance(part, str) for part in src):
                if errors is not None:
                    errors.append("notebook source array must contain strings")
                continue
            src = "".join(src)
        if not isinstance(src, str):
            if errors is not None:
                errors.append("notebook source must be text or an array of strings")
            continue
        out.append(src)
    if cells is not None:
        cells.extend(out)
    return "\n".join(out)


def _binary_mime(key: str) -> bool:
    """Whether a MIME bundle key holds base64-encoded binary data, as nbformat stores it."""
    key = key.lower()
    if key.startswith("image/"):
        return key != "image/svg+xml"  # SVG is XML text, read like any other output
    return key.startswith(("audio/", "video/")) or key == "application/pdf"


# Standard base64 as nbformat writes it: the alphabet, with padding only at the very end.
_BASE64_DATA = re.compile(r"[A-Za-z0-9+/]*+={0,2}")
# Leading bytes of the image, audio, video and PDF formats a notebook embeds.
_BINARY_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF-", b"II*\x00", b"MM\x00*",
    b"\x00\x00\x01\x00", b"OggS", b"fLaC", b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"\x1aE\xdf\xa3",
)  # fmt: skip


def _base64_binary(parts: list[str]) -> bool:
    """Whether ``parts`` (one value, maybe split in lines) are strict base64 of an image, audio, video or PDF.

    The value is read whole: its lines joined, every line but the last of one
    width (as a writer wraps it), padding only at its very end, and the whole
    of it decoding (``validate``) to bytes that begin with such a file's
    signature. Anything looser stays text and is scanned: a key spelled in the
    alphabet after a padded first line is not image data.
    """
    if not parts:
        return False
    lines = "".join(parts).replace("\r\n", "\n").split("\n")
    if lines and not lines[-1]:
        lines.pop()
    if not lines or any(len(line) != len(lines[0]) for line in lines[:-1]) or len(lines[-1]) > len(lines[0]):
        return False
    value = "".join(lines)
    if len(value) % 4 or not _BASE64_DATA.fullmatch(value):
        return False
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError:
        return False
    return data.startswith(_BINARY_SIGNATURES) or (
        data[4:8] == b"ftyp" or (data[:4] == b"RIFF" and data[8:12] in {b"WEBP", b"WAVE", b"AVI "})
    )


def _binary_output_data(cell: dict[str, Any]) -> list[str]:
    """The base64 binary strings of a cell's output MIME bundles and attachments, in document order.

    Only ``outputs[*].data`` and ``attachments.*`` are MIME bundles in nbformat 4;
    a binary MIME key anywhere else (cell or notebook metadata) holds ordinary data.
    """
    bundles: list[Any] = []
    for key, value in cell.items():
        if key == "outputs" and isinstance(value, list):
            bundles.extend(output.get("data") for output in value if isinstance(output, dict))
        elif key == "attachments" and isinstance(value, dict):
            bundles.extend(value.values())
    found: list[str] = []
    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        for key, value in bundle.items():
            parts = [value] if isinstance(value, str) else value
            if (
                isinstance(key, str)
                and _binary_mime(key)
                and isinstance(parts, list)
                and all(isinstance(part, str) for part in parts)
                and _base64_binary(parts)
            ):
                found.extend(parts)
    return found


# Missed finds that end a notebook rebuild (``notebook_without_binary_data``).
# A writer emits plain base64, so a find misses only on an unusual escape, and
# each miss scans to the document's end: a hostile notebook spelling every
# value with escapes must not buy that scan per value.
_MAX_MISSED_BINARY = 8


def notebook_without_binary_data(document: str, binary: list[str]) -> tuple[str, int]:
    """``document`` with the ``binary`` output strings emptied, and the characters removed.

    A notebook keeps rendered images, audio, video and PDFs of its outputs and
    markdown attachments as base64 strings under their MIME type
    (``"image/png": "iVBOR..."``), and that data is most of a large notebook.
    ``binary`` holds those strings in document order (``notebook_to_source``
    collects them: only from output bundles and attachments, only strict base64
    that decodes to such a file's signature, and the file scanner keeps any the
    credential pass matches), so emptying them loses no credential the scanner
    would read. Every text output
    (streams, tracebacks, ``text/plain``, HTML, JSON, SVG) and all metadata stay.
    A string is found by its JSON encoding, which holds no quote or raw line
    break, so each match is one whole string and every line keeps its number;
    one that is not found (an unusual escape) is kept and read, and after
    ``_MAX_MISSED_BINARY`` misses the rebuild stops, so a notebook that spells
    its values with escapes no writer emits keeps its oversize gap instead of
    buying a document-length scan per value.
    """
    out: list[str] = []
    missed = removed = position = 0
    for part in binary:
        encoded = json.dumps(part)
        at = document.find(encoded, position)
        if at < 0:
            missed += 1
            if missed > _MAX_MISSED_BINARY:
                break
            continue
        out.extend((document[position:at], '""'))
        removed += len(encoded) - 2
        position = at + len(encoded)
    out.append(document[position:])
    return "".join(out), removed


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing.

    ISO 8601, epoch seconds / millis / micros / nanos, Go ``time.Time.String()``
    output and RFC 2822 dates. Anything else is ``None``.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            v = float(value)
        except OverflowError:
            return None
        if not math.isfinite(v):
            return None
        # Seconds, then milli-, micro- and nanoseconds; each unit's range ends
        # before the next begins for dates before the year 33658.
        if v > 1e18:
            v /= 1e9
        elif v > 1e15:
            v /= 1e6
        elif v > 1e12:
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if len(s) > 64:
        # No supported timestamp representation is this long; hostile claims
        # (thousands of digits) must not reach int()/float() conversion.
        return None
    if _CALENDAR_DAY_RX.fullmatch(s):
        # Eight digits starting 19xx/20xx are a calendar day (yyyymmdd, as in
        # a log's ``date`` field); as epoch seconds they would all fall in
        # 1970-1973. An impossible day is no timestamp at all.
        try:
            return datetime.strptime(s, "%Y%m%d").replace(tzinfo=UTC)
        except ValueError:
            return None
    if _EPOCH_RX.fullmatch(s):
        return parse_timestamp(float(s))
    s = s.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return _go_or_rfc2822_time(s)


# Go's time.Time.String(): "2006-01-02 15:04:05.999999999 -0700 MST", with an
# optional monotonic clock reading ("m=+0.000000001"). Every part is bounded.
_GO_TIME_RX = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))? ([+-]\d{4})"
    r"(?: [A-Za-z0-9+:-]{1,16})?(?: m=[+-]\d{1,20}(?:\.\d{1,9})?)?"
)


def _go_or_rfc2822_time(s: str) -> datetime | None:
    """Parse Go ``time.Time.String()`` output or an RFC 2822 date (mail, HTTP, syslog exporters)."""
    from email.utils import parsedate_to_datetime

    go = _GO_TIME_RX.fullmatch(s)
    if go:
        fraction = (go.group(2) or "")[:6].ljust(6, "0")
        try:
            return datetime.strptime(f"{go.group(1)}.{fraction} {go.group(3)}", "%Y-%m-%d %H:%M:%S.%f %z")
        except ValueError:
            return None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def to_iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat() if dt else None


def flatten(d: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten nested dicts/lists into dotted keys (for schema sniffing of logs)."""
    if out is None:
        out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                flatten(v, key + ".", out)
            else:
                out[key] = v
    elif isinstance(d, list):
        for i, v in enumerate(d[:50]):
            key = f"{prefix}{i}"
            if isinstance(v, (dict, list)):
                flatten(v, key + ".", out)
            else:
                out[key] = v
    return out


def get_path(d: dict[str, Any], *paths: str, default: Any = None) -> Any:
    """Return the first present value among dotted paths."""
    for path in paths:
        cur: Any = d
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return default


def truncate(s: str | None, n: int = 200) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[: n - 1] + "…"


def line_counter(text: str) -> Callable[[int], int]:
    """Map offsets in ``text`` to 1-based line numbers, counting each newline once.

    Successive regex matches arrive in order, so each call counts only the
    newlines since the previous offset: numbering every match of a scanned file
    stays linear in its length. Counting from the start for every match is
    quadratic, and a file with thousands of imports would then exhaust the match
    deadline it is charged against. An earlier offset recounts from the start.
    """
    position, line = 0, 1

    def line_at(offset: int) -> int:
        nonlocal position, line
        if offset < position:
            position, line = 0, 1
        line += text.count("\n", position, offset)
        position = offset
        return line

    return line_at


def python_source_lines(text: str) -> list[str]:
    """Keep original physical lines for Python AST byte-column coordinates.

    Python accepts LF, CRLF and CR as source line endings. Other separators
    accepted by str.splitlines() are literal content and must not shift later
    constructor or registered-tool spans.
    """
    lines: list[str] = []
    start = 0
    for match in re.finditer(r"\r\n|\r|\n", text):
        lines.append(text[start : match.end()])
        start = match.end()
    lines.append(text[start:])
    return lines


_URL_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*+://", re.IGNORECASE)


def host_of(url: str | None) -> str | None:
    """Return the lowercase host of ``url`` (RFC 3986 authority; scheme optional).

    Userinfo before the last ``@`` and the port are removed, and a bracketed
    IPv6 literal is returned without its brackets. An authority such as
    ``api.openai.com:443@evil.example`` therefore names ``evil.example``, the host
    a client connects to, never the userinfo.
    """
    if not url:
        return None
    rest = url.strip()
    scheme = _URL_SCHEME.match(rest)
    if scheme:
        rest = rest[scheme.end() :]
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0].rpartition("@")[2]
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end] if end > 0 else ""
    else:
        host = authority.split(":", 1)[0]
    return host.lower() or None
