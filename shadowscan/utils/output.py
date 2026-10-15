"""Atomic, owner-readable output files for sensitive scan artifacts."""

from __future__ import annotations

import os
import secrets
import stat
import unicodedata
from pathlib import Path

from shadowscan.utils.files import open_confined_directory, require_no_symlinks

# Characters outside the format category that also show nothing: the combining grapheme
# joiner, the variation selectors (which can carry a hidden message as tag characters
# can), the Hangul fillers and the blank Braille pattern.
# The bidi, zero-width and tag blocks are escaped whole, including their unassigned
# code points, which a later Unicode version may assign.
_INVISIBLE = frozenset(
    {
        0x034F,
        0x115F,
        0x1160,
        0x2800,
        0x3164,
        0xFFA0,
        *range(0x200B, 0x2010),
        *range(0x202A, 0x202F),
        *range(0x2060, 0x2070),
        *range(0xFE00, 0xFE10),
        *range(0xE0000, 0xE0080),
        *range(0xE0100, 0xE01F0),
    }
)


def shown_escaped(char: str) -> bool:
    """Whether :func:`terminal_text` renders ``char`` as an escape rather than as itself."""
    code = ord(char)
    return (
        code < 32
        or 0x7F <= code <= 0x9F
        or 0x2028 <= code <= 0x2029
        or 0xD800 <= code <= 0xDFFF
        or code in _INVISIBLE
        or unicodedata.category(char) == "Cf"
    )


def terminal_text(value: object) -> str:
    """Display untrusted values without executing terminal control sequences.

    Rich's Text/markup=False prevents markup interpretation but still passes
    through ANSI escape sequences. Render control and bidi-formatting characters
    visibly so repository names, evidence and diagnostics cannot alter terminal
    state or conceal/reorder a report. The same goes for the characters that
    show nothing at all: every format character (zero-width characters, the
    byte-order mark, the soft hyphen, interlinear annotation marks, Unicode tag
    characters, which can carry a hidden message), the variation selectors and
    other blank characters in ``_INVISIBLE``, and the lone surrogates that no
    encoder accepts. Call before adding intentional newlines.
    """
    out = []
    for char in str(value):
        if not shown_escaped(char):
            out.append(char)
            continue
        code = ord(char)
        out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
    return "".join(out)


def encodable_text(text: str) -> str:
    """``text`` as a stream can encode it: a lone surrogate becomes a visible ``\\udXXX`` escape.

    A name read from an export can hold a lone surrogate ('x\\ud800y' decoded from JSON),
    which no UTF-8 encoder accepts: writing it failed the report or printed a traceback.
    Nothing is dropped, and text that is already encodable is returned as it is.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="backslashreplace").decode("utf-8")
    return text


def terminal_report_text(value: str, report_format: str) -> str:
    """Neutralize controls in HTML/CSV only when publishing to a terminal.

    JSON and SARIF encoders escape controls themselves, and the Markdown
    renderer has context-specific escaping. HTML and CSV deliberately preserve
    source text in saved artifacts, so applying this at the stdout boundary
    prevents OSC/ANSI/C1 and bidi commands from reaching a terminal without
    changing file output. Generated CSV row separators remain newlines; carriage
    returns and every other control are rendered visibly.
    """
    if report_format not in {"csv", "html"}:
        return value
    normalized = value.replace("\r\n", "\n")
    return "\n".join(terminal_text(line) for line in normalized.split("\n"))


def prepare_private_directory(path: str | Path) -> Path:
    """Create private storage without changing permissions on an existing directory."""
    target = require_no_symlinks(Path(path).expanduser())
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("output directory must be owned by the current user with private mode 0700")
    finally:
        os.close(fd)
    return target


def _existing_stat(target: Path) -> os.stat_result | None:
    """Return ``lstat`` for an existing output path, or None if it is absent."""
    try:
        return os.lstat(target)
    except FileNotFoundError:
        return None


def _require_private_pipe(info: os.stat_result) -> None:
    # Another local user can plant a pipe at a report path in a shared
    # directory such as /tmp; writing into it would hand them the report.
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("refusing a named pipe not owned by the current user with private mode 0600")


def _write_in_place(target: Path, data: bytes) -> None:
    """Write into an existing character device or named pipe without replacing it.

    ``O_NOFOLLOW`` refuses a symlink swapped in after the type check, and the
    descriptor's own type, owner and mode are checked again, so a regular file
    or foreign pipe swapped in is never written. Nothing is truncated. The open
    is non-blocking, so a named pipe without a reader fails at once (ENXIO)
    instead of hanging; the descriptor is made blocking again for the write.
    """
    flags = (
        os.O_WRONLY
        | os.O_NONBLOCK
        | getattr(os, "O_NOCTTY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(target, flags)
    try:
        info = os.fstat(fd)
        if stat.S_ISFIFO(info.st_mode):
            _require_private_pipe(info)
        elif not stat.S_ISCHR(info.st_mode):
            raise ValueError("output file changed type before writing")
        os.set_blocking(fd, True)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def _private_output_parent(target: Path) -> Path:
    """The real directory an output goes into, refusing a link another user could have planted.

    Every symbolic link on the way to the output's directory must be owned by root (a
    system link such as macOS's ``/tmp``) or by the current user: another local user can
    plant a link in a shared directory and receive the report. The directory is then
    named by its real path, with no link left in it.
    """
    absolute = Path(os.path.abspath(target)).parent
    for part in (*reversed(absolute.parents), absolute):
        try:
            info = os.lstat(part)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode) and info.st_uid not in (0, os.geteuid()):
            raise ValueError("refusing an output path through a symbolic link owned by another user")
    return Path(os.path.realpath(absolute))


def _temporary_name(name: str) -> str:
    # The name stays within NAME_MAX for any legal destination name.
    return f".{name[:200]}.{secrets.token_hex(4)}"


def write_private_text(path: str | Path, text: str) -> None:
    """Replace an output atomically without following an existing file symlink.

    The output's directory is opened without following a link in any component of
    its real path, after a check that no link on the way to it belongs to another
    user (see :func:`_private_output_parent`); the temporary file is created and
    renamed relative to that open directory, so a directory swapped for a link
    afterwards is not written through. The temporary file is created with mode
    0600, including when replacing a more permissive report. Failed writes leave
    the previous report intact.

    An existing character device (``-o /dev/null``) is written in place:
    renaming a temporary file over it would replace the device node itself,
    which succeeds when running as root. An existing named pipe is written in
    place only when the current user owns it with private mode 0600 and a
    reader already has it open. Any other existing path that is not a regular
    file (a socket, directory or block device) is refused.
    """
    name = Path(path).name
    if name in ("", ".", ".."):
        raise ValueError("refusing a non-regular output file")
    parent = _private_output_parent(Path(path))
    target = parent / name
    info = _existing_stat(target)
    if info is not None:
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            raise ValueError("refusing a symlink output file")
        if stat.S_ISFIFO(mode):
            _require_private_pipe(info)
        if stat.S_ISFIFO(mode) or stat.S_ISCHR(mode):
            _write_in_place(target, text.encode("utf-8", errors="backslashreplace"))
            return
        if not stat.S_ISREG(mode):
            raise ValueError("refusing a non-regular output file")
    directory = open_confined_directory(parent)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        while True:
            temporary = _temporary_name(name)
            try:
                fd = os.open(temporary, flags, 0o600, dir_fd=directory)
                break
            except FileExistsError:
                continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    finally:
        os.close(directory)
