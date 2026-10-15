"""Report outputs must never replace a device node, pipe or other special file.

Renaming a private temporary file over an existing path is right for regular
files, but for ``-o /dev/null`` run as root it replaces the system's null
device with a regular file. These tests use a named pipe, a pseudo-terminal
and a socket so a regression cannot damage the host running them.
"""

from __future__ import annotations

import errno
import json
import os
import select
import socket
import stat
import tempfile
import threading
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.utils import output
from shadowscan.utils.output import write_private_text


def _drain(fd: int) -> bytes:
    chunks = []
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EAGAIN:
                break
            raise
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _private_pipe(path: Path) -> Path:
    os.mkfifo(path, 0o600)
    os.chmod(path, 0o600)
    return path


def _fake_private_pipe_stat() -> os.stat_result:
    return os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 1, os.geteuid(), os.getegid(), 0, 0, 0, 0))


def test_report_to_named_pipe_is_written_in_place(tmp_path):
    pipe = _private_pipe(tmp_path / "report.pipe")
    # A non-blocking reader lets the writer open the pipe, and lets a
    # regression that renames over the pipe fail instead of hanging.
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        write_private_text(pipe, "report body")
        assert stat.S_ISFIFO(os.lstat(pipe).st_mode)
        assert _drain(reader) == b"report body"
    finally:
        os.close(reader)
    assert [entry.name for entry in tmp_path.iterdir()] == ["report.pipe"]


def test_report_to_character_device_is_written_in_place():
    termios = pytest.importorskip("termios")
    try:
        controller, terminal = os.openpty()
    except OSError:
        pytest.skip("pseudo-terminals are unavailable")
    try:
        device = os.ttyname(terminal)
        attrs = termios.tcgetattr(terminal)
        attrs[1] &= ~termios.OPOST  # deliver the bytes unchanged
        termios.tcsetattr(terminal, termios.TCSANOW, attrs)
        write_private_text(device, "report body")
        assert stat.S_ISCHR(os.lstat(device).st_mode)
        ready, _, _ = select.select([controller], [], [], 5)
        assert ready, "nothing was written to the character device"
        assert os.read(controller, 1024) == b"report body"
    finally:
        os.close(terminal)
        os.close(controller)


def test_report_refuses_a_socket_without_replacing_it():
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = Path(directory) / "s"
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
                pytest.skip("this worker cannot create Unix sockets")
            raise
        try:
            server.bind(str(path))
            with pytest.raises(ValueError, match="non-regular"):
                write_private_text(path, "report body")
            assert stat.S_ISSOCK(os.lstat(path).st_mode)
            assert sorted(entry.name for entry in Path(directory).iterdir()) == ["s"]
        finally:
            server.close()


def test_report_refuses_a_directory_without_touching_it(tmp_path):
    target = tmp_path / "reports"
    target.mkdir()
    (target / "kept").write_text("kept")
    with pytest.raises(ValueError, match="non-regular"):
        write_private_text(target, "report body")
    assert (target / "kept").read_text() == "kept"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["reports"]


def test_in_place_write_rechecks_the_opened_file_type(tmp_path, monkeypatch):
    # Simulate a regular file swapped in after the type check: the in-place
    # path must not write it without the atomic private-mode replacement.
    target = tmp_path / "report"
    target.write_text("previous")
    monkeypatch.setattr(output, "_existing_stat", lambda path: _fake_private_pipe_stat())
    with pytest.raises(ValueError, match="changed type"):
        write_private_text(target, "report body")
    assert target.read_text() == "previous"


def test_report_refuses_a_named_pipe_owned_by_another_user(tmp_path, monkeypatch):
    # A pipe planted at the report path in a shared directory must not
    # receive the report. Pretend to be another user rather than chown.
    pipe = _private_pipe(tmp_path / "report.pipe")
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        monkeypatch.setattr(output.os, "geteuid", lambda: os.stat(pipe).st_uid + 1)
        with pytest.raises(ValueError, match="named pipe"):
            write_private_text(pipe, "report body")
        monkeypatch.undo()
        assert _drain(reader) == b""
    finally:
        os.close(reader)
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)
    assert [entry.name for entry in tmp_path.iterdir()] == ["report.pipe"]


def test_report_refuses_a_named_pipe_open_to_other_users(tmp_path):
    pipe = tmp_path / "report.pipe"
    os.mkfifo(pipe)
    os.chmod(pipe, 0o644)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(ValueError, match="private mode"):
            write_private_text(pipe, "report body")
        assert _drain(reader) == b""
    finally:
        os.close(reader)
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)


def test_report_refuses_a_named_pipe_with_owner_execute_bits(tmp_path):
    # The mode check must require exactly 0600, matching what the error
    # message and CHANGELOG both claim; 0700 has no group/other access either,
    # but execute bits on a FIFO are meaningless and the spec is 0600 exactly.
    pipe = tmp_path / "report.pipe"
    os.mkfifo(pipe)
    os.chmod(pipe, 0o700)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(ValueError, match="private mode 0600"):
            write_private_text(pipe, "report body")
        assert _drain(reader) == b""
    finally:
        os.close(reader)
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)


def test_in_place_write_rechecks_the_opened_pipe_owner_and_mode(tmp_path, monkeypatch):
    # The pipe passed the first check but is open to other users by the time
    # it is opened; the descriptor check must refuse it before writing.
    pipe = tmp_path / "report.pipe"
    os.mkfifo(pipe)
    os.chmod(pipe, 0o644)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        monkeypatch.setattr(output, "_existing_stat", lambda path: _fake_private_pipe_stat())
        with pytest.raises(ValueError, match="private mode"):
            write_private_text(pipe, "report body")
        assert _drain(reader) == b""
    finally:
        os.close(reader)


def test_report_to_named_pipe_without_reader_fails_instead_of_hanging(tmp_path):
    pipe = _private_pipe(tmp_path / "report.pipe")
    outcome: list[BaseException | None] = []

    def attempt() -> None:
        try:
            write_private_text(pipe, "report body")
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion below
            outcome.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive():
        # Release a blocked writer so the regression is reported, not hung.
        release = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
        worker.join(timeout=5)
        os.close(release)
        pytest.fail("writing to a named pipe without a reader blocked")
    assert len(outcome) == 1 and isinstance(outcome[0], OSError)
    assert outcome[0].errno == errno.ENXIO
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)


def test_cli_report_to_named_pipe_keeps_the_pipe(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    pipe = _private_pipe(tmp_path / "report.pipe")
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        result = CliRunner().invoke(main, ["code", str(source), "--format", "json", "-o", str(pipe)])
        received = _drain(reader)
    finally:
        os.close(reader)
    assert result.exit_code == 0, result.output
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)
    assert "findings" in json.loads(received)


def test_report_is_not_written_through_a_directory_link_another_user_owns(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "reports"
    link.symlink_to(victim, target_is_directory=True)
    real_lstat = os.lstat

    def foreign_link(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == os.fspath(link):
            fields = list(info)
            fields[stat.ST_UID] = os.geteuid() + 4242
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(output.os, "lstat", foreign_link)
    with pytest.raises(ValueError, match="symbolic link owned by another user"):
        write_private_text(link / "report.json", "report body")
    assert list(victim.iterdir()) == []


def test_report_through_the_operators_own_directory_link_lands_in_its_target(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    (tmp_path / "alias").symlink_to(target, target_is_directory=True)
    write_private_text(tmp_path / "alias" / "report.json", "report body")
    written = target / "report.json"
    assert written.read_text() == "report body"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert sorted(entry.name for entry in target.iterdir()) == ["report.json"]


def test_a_long_legal_output_name_is_written(tmp_path):
    name = "r" * 250 + ".json"
    write_private_text(tmp_path / name, "report body")
    assert (tmp_path / name).read_text() == "report body"


_FOREIGN_UID = 4242


@pytest.fixture(params=["lchown", "lstat"])
def give_away(request, monkeypatch):
    """Make a link another user's: really, with lchown (root only), or as lstat reports it.

    Only a link that is really another user's shows that ``os.path.realpath`` and the
    kernel follow it whatever a patched lstat says; the lstat variant runs everywhere.
    """
    if request.param == "lchown":
        if not hasattr(os, "lchown") or not hasattr(os, "geteuid") or os.geteuid() != 0:
            pytest.skip("giving a symbolic link to another user needs root and lchown")
        return lambda link: os.lchown(link, _FOREIGN_UID, -1)
    foreign: set[str] = set()
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) in foreign:
            fields = list(info)
            fields[stat.ST_UID] = os.geteuid() + _FOREIGN_UID
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(output.os, "lstat", lstat)
    return lambda link: foreign.add(os.fspath(link))


def _directory_link(link: Path, target: Path) -> Path:
    link.symlink_to(target, target_is_directory=True)
    return link


def test_report_is_not_written_through_a_foreign_link_behind_the_operators_own(tmp_path, give_away):
    # mine (the operator's) -> shared (another user's) -> victim/
    victim = tmp_path / "victim"
    victim.mkdir()
    shared = _directory_link(tmp_path / "shared", victim)
    give_away(shared)
    _directory_link(tmp_path / "mine", shared)
    with pytest.raises(ValueError, match="symbolic link owned by another user"):
        write_private_text(tmp_path / "mine" / "report.json", "report body")
    assert list(victim.iterdir()) == []


def test_report_is_not_written_through_a_foreign_link_inside_a_link_target(tmp_path, give_away):
    # mine -> shared/sub, where shared is another user's link to victim/
    victim = tmp_path / "victim"
    (victim / "sub").mkdir(parents=True)
    give_away(_directory_link(tmp_path / "shared", victim))
    _directory_link(tmp_path / "mine", Path("shared") / "sub")
    with pytest.raises(ValueError, match="symbolic link owned by another user"):
        write_private_text(tmp_path / "mine" / "report.json", "report body")
    assert list((victim / "sub").iterdir()) == []


def test_a_foreign_link_planted_where_a_component_was_missing_is_not_followed(
    tmp_path, monkeypatch, give_away
):
    victim = tmp_path / "victim"
    victim.mkdir()
    late = tmp_path / "late"
    checked_lstat = os.lstat
    planted: list[Path] = []

    def lstat(path, *args, **kwargs):
        try:
            return checked_lstat(path, *args, **kwargs)
        except FileNotFoundError:
            # Another user plants the link right after the component was found missing.
            if os.fspath(path) == os.fspath(late) and not planted:
                planted.append(_directory_link(late, victim))
                give_away(late)
            raise

    monkeypatch.setattr(output.os, "lstat", lstat)
    with pytest.raises(FileNotFoundError):
        write_private_text(late / "report.json", "report body")
    assert planted == [late]
    assert list(victim.iterdir()) == []


@pytest.mark.skipif(
    not hasattr(os, "lchown") or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="links owned by root and by another operator need root and lchown",
)
def test_report_through_the_operators_own_and_root_owned_links_lands_in_the_target(tmp_path, monkeypatch):
    # Run as a non-root operator: their own link and a root-owned system link (macOS's
    # /tmp -> private/tmp) are followed, here chained, the second written relative.
    operator = _FOREIGN_UID + 1
    real = tmp_path / "private" / "reports"
    real.mkdir(parents=True)
    os.lchown(_directory_link(tmp_path / "system", Path("private")), 0, -1)
    os.lchown(_directory_link(tmp_path / "mine", tmp_path / "system" / "reports"), operator, -1)
    monkeypatch.setattr(output.os, "geteuid", lambda: operator)
    write_private_text(tmp_path / "mine" / "report.json", "report body")
    monkeypatch.undo()
    written = real / "report.json"
    assert written.read_text() == "report body"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert sorted(entry.name for entry in real.iterdir()) == ["report.json"]


def test_report_through_relative_links_and_parent_steps_lands_in_the_real_directory(tmp_path):
    real = tmp_path / "deep" / "real"
    real.mkdir(parents=True)
    _directory_link(tmp_path / "deep" / "inner", Path("real"))
    _directory_link(tmp_path / "outer", Path("deep") / "inner" / ".." / "real")
    write_private_text(tmp_path / "outer" / "report.json", "report body")
    assert (real / "report.json").read_text() == "report body"
    assert sorted(entry.name for entry in real.iterdir()) == ["report.json"]


def test_parent_steps_in_the_output_path_are_resolved_before_links(tmp_path):
    # '..' in the given path is lexical: 'mine/../r.json' lands beside the link, not in
    # the parent of its target, where the kernel's own resolution would put it.
    real = tmp_path / "elsewhere" / "real"
    real.mkdir(parents=True)
    _directory_link(tmp_path / "mine", real)
    write_private_text(tmp_path / "mine" / ".." / "report.json", "report body")
    assert (tmp_path / "report.json").read_text() == "report body"
    assert not (tmp_path / "elsewhere" / "report.json").exists()


def test_report_in_a_plain_nested_directory_is_written(tmp_path):
    directory = tmp_path / "a" / "b"
    directory.mkdir(parents=True)
    write_private_text(directory / "report.json", "report body")
    assert (directory / "report.json").read_text() == "report body"
    assert stat.S_IMODE((directory / "report.json").stat().st_mode) == 0o600


def test_report_into_a_missing_directory_is_refused(tmp_path):
    with pytest.raises(FileNotFoundError):
        write_private_text(tmp_path / "missing" / "report.json", "report body")
    assert list(tmp_path.iterdir()) == []


def test_a_directory_link_loop_is_refused(tmp_path):
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    with pytest.raises(ValueError, match="too many symbolic links"):
        write_private_text(tmp_path / "a" / "report.json", "report body")


# NAME_MAX counts bytes. Each name is a legal destination of 253-255 bytes but well under
# 200 code points, so a temporary name cut by code points would exceed NAME_MAX.
_MULTIBYTE_NAMES = [
    pytest.param("文" * 83 + ".json", id="cjk-254-bytes"),
    pytest.param("\U0001f600" * 62 + ".json", id="emoji-253-bytes"),
    pytest.param("é" * 125 + ".json", id="latin1-255-bytes"),
]


@pytest.mark.parametrize("name", _MULTIBYTE_NAMES)
def test_temporary_name_fits_name_max_in_bytes_and_keeps_whole_characters(name):
    assert len(os.fsencode(name)) <= 255
    temporary = output._temporary_name(name)
    assert len(os.fsencode(temporary)) <= 255
    os.fsencode(temporary).decode("utf-8")  # no character split at the cut
    assert temporary.startswith(".")


@pytest.mark.parametrize("name", _MULTIBYTE_NAMES)
def test_a_long_legal_multibyte_output_name_is_written(tmp_path, name):
    target = tmp_path / name
    try:
        target.touch()
    except OSError as exc:  # pragma: no cover - a filesystem with a smaller limit
        pytest.skip(f"filesystem refuses the destination name itself: {exc}")
    target.unlink()
    write_private_text(target, "report body")
    assert target.read_text() == "report body"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [entry.name for entry in tmp_path.iterdir()] == [name]
