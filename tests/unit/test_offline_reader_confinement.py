"""The whole-file and line-oriented offline readers share one confined open path.

Both readers, and the policy reader, must refuse a symlink in any path
component and anything that is not a regular file, enforce their own byte
limits, and read a normal file identically.
"""

from __future__ import annotations

import gc
import os
import stat
from pathlib import Path

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import ScanStats, Surface
from shadowscan.utils.files import NotRegularFileError, changed_since, open_confined_file, read_policy_text

DATA = b'{"a":1}\n{"b":2}\n'


class _Probe(BaseConnector):
    name = "test.reader"
    surface = Surface.CODE

    def collect(self):
        return []

    def analyze(self, records):
        return []


def _probe(index, **config) -> _Probe:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01T00:00:00Z")
    probe = _Probe(ctx)
    probe._offline_bytes_read = 0
    return probe


def _lines(probe: _Probe, path: Path) -> bytes:
    return "".join(probe._iter_bounded_lines(path, probe._offline_budget())).encode()


def _assert_all_readers_refuse(probe: _Probe, path: Path, *, reason: str) -> None:
    """Every reader fails closed on ``path``; ``reason`` is the offline error substring."""
    assert probe._read_offline_bytes(path, probe._offline_budget()) is None
    assert probe._read_offline_bytes(path) is None
    assert _lines(probe, path) == b""
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.errors and probe.ctx.stats.warnings
    assert all(reason in message for message in probe.ctx.stats.errors)
    with pytest.raises((OSError, ValueError)):
        read_policy_text(path)


def test_readers_return_identical_bytes_for_regular_file(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index)

    with_budget = probe._read_offline_bytes(source, probe._offline_budget())
    without_budget = probe._read_offline_bytes(source)

    assert with_budget == without_budget == _lines(probe, source) == DATA
    assert read_policy_text(source) == DATA.decode()
    assert not probe.ctx.stats.incomplete
    assert not probe.ctx.stats.errors and not probe.ctx.stats.warnings


def test_readers_refuse_symlinked_file(tmp_path, index):
    target = tmp_path / "outside.jsonl"
    target.write_bytes(DATA)
    link = tmp_path / "records.jsonl"
    link.symlink_to(target)
    probe = _probe(index)

    _assert_all_readers_refuse(probe, link, reason="could not be securely read")

    assert all("could not be read" in warning for warning in probe.ctx.stats.warnings)
    # A link the confined open refuses (ELOOP) is a link not followed, in both readers.
    assert probe.ctx.stats.incomplete_reasons == {"unresolved-link": 3}
    with pytest.raises(OSError):
        read_policy_text(link)


def test_readers_refuse_symlinked_directory_component(tmp_path, index):
    real = tmp_path / "real"
    real.mkdir()
    (real / "records.jsonl").write_bytes(DATA)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    through_link = linked / "records.jsonl"
    assert through_link.is_file() and not through_link.is_symlink()
    probe = _probe(index)

    _assert_all_readers_refuse(probe, through_link, reason="could not be securely read")
    assert probe.ctx.stats.incomplete_reasons == {"unresolved-link": 3}

    with pytest.raises(OSError):
        read_policy_text(through_link)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable on this platform")
def test_readers_refuse_fifo_without_blocking(tmp_path, index):
    fifo = tmp_path / "records.jsonl"
    os.mkfifo(fifo)
    probe = _probe(index)

    _assert_all_readers_refuse(probe, fifo, reason="offline input is not a regular file")

    assert all("offline input is not a regular file" in warning for warning in probe.ctx.stats.warnings)
    with pytest.raises(NotRegularFileError, match="policy input is not a regular file"):
        read_policy_text(fifo)
    assert issubclass(NotRegularFileError, ValueError)


def _character_device(tmp_path: Path) -> Path | None:
    """A character device reachable without symlinks: a fresh node when permitted, else a system one."""
    candidates: list[Path] = []
    if hasattr(os, "mknod") and hasattr(os, "makedev"):
        created = tmp_path / "device"
        try:
            os.mknod(created, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except OSError:
            pass
        else:
            candidates.append(created)
    candidates.extend((Path("/dev/null"), Path("/dev/zero")))
    for candidate in candidates:
        try:
            if not stat.S_ISCHR(os.stat(candidate).st_mode):
                continue
        except OSError:
            continue
        if not any(part.is_symlink() for part in (candidate, *candidate.parents)):
            return candidate
    return None


def test_readers_refuse_device(tmp_path, index):
    device = _character_device(tmp_path)
    if device is None:
        pytest.skip("no plain character device available")
    probe = _probe(index)

    _assert_all_readers_refuse(probe, device, reason="offline input is not a regular file")

    with pytest.raises(NotRegularFileError):
        read_policy_text(device)


def test_readers_refuse_directory(tmp_path, index):
    probe = _probe(index)

    _assert_all_readers_refuse(probe, tmp_path, reason="offline input is not a regular file")
    # Issue #264: both readers count a special file in the file's place alike
    # (the whole-file reader with and without a budget, then the line reader), as
    # unscanned input, the way code.filesystem counts a non-regular entry: it is no link.
    assert probe.ctx.stats.incomplete_reasons == {"unscanned-input": 3}


def test_readers_count_a_file_over_the_per_file_cap_as_oversize(tmp_path, index):
    # Issue #264: a file skipped whole for its size is an oversize file in either reader.
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)

    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert _lines(probe, source) == b""
    assert probe.ctx.stats.incomplete_reasons == {"oversize-file": 2}


def test_line_reader_counts_a_corrupt_gzip_as_unparsed_input(tmp_path, index):
    # Issue #264: gzip.BadGzipFile is an OSError, but a corrupt archive is
    # content that did not parse, not a permission or credential problem.
    source = tmp_path / "records.jsonl.gz"
    source.write_bytes(b"not a gzip stream\n")
    probe = _probe(index)

    assert list(probe._iter_bounded_lines(source, probe._offline_budget(), compressed=True)) == []
    assert probe.ctx.stats.warnings == ["test.reader: offline input could not be read (BadGzipFile)"]
    assert probe.ctx.stats.incomplete_reasons == {"unparsed-input": 1}


def test_whole_file_reader_enforces_per_file_limit(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)

    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_file_bytes reached; oversized offline input was skipped"
    ]

    probe = _probe(index, max_input_file_bytes=len(DATA), max_input_bytes=1024)
    assert probe._read_offline_bytes(source, probe._offline_budget()) == DATA


def test_whole_file_reader_enforces_aggregate_budget(tmp_path, index):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_bytes(DATA)
    second.write_bytes(DATA)
    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    budget = probe._offline_budget()

    assert probe._read_offline_bytes(first, budget) == DATA
    assert budget.bytes_read == len(DATA)
    assert probe._read_offline_bytes(second, budget) is None
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; oversized offline input was skipped"
    ]

    # Without a budget the connector-wide counter is charged and the file is an error.
    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    assert probe._read_offline_bytes(first) == DATA
    assert probe._offline_bytes_read == len(DATA)
    assert probe._read_offline_bytes(second) is None
    assert probe.ctx.stats.errors == ["test.reader: offline input exceeds the byte limit"]


def test_line_reader_enforces_per_file_limit_before_reading(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)

    assert _lines(probe, source) == b""
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.warnings == [f"test.reader: max_input_file_bytes ({len(DATA) - 1}) reached"]


def test_line_reader_streams_records_up_to_the_aggregate_budget(tmp_path, index):
    """The two readers bound the aggregate budget differently on purpose.

    The line reader charges the budget per line and yields the records that
    fit; the whole-file reader rejects the same file outright.
    """
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    first_line = DATA.splitlines(keepends=True)[0]
    probe = _probe(index, max_input_bytes=len(first_line), max_input_file_bytes=1024)

    lines = list(probe._iter_bounded_lines(source, probe._offline_budget()))

    assert lines == [first_line.decode()]
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; remaining offline input was skipped"
    ]

    probe = _probe(index, max_input_bytes=len(first_line), max_input_file_bytes=1024)
    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; oversized offline input was skipped"
    ]


def test_readers_report_a_file_rewritten_during_the_read(tmp_path, index, monkeypatch):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    monkeypatch.setattr("shadowscan.connectors.base.changed_since", lambda before, fd: True)
    probe = _probe(index)

    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert _lines(probe, source) == DATA
    assert probe.ctx.stats.errors == [
        "test.reader: offline input changed while being read",
        "test.reader: offline input changed while being read",
    ]
    assert probe.ctx.stats.incomplete


def test_changed_since_detects_rewrite_of_the_open_descriptor(tmp_path):
    source = tmp_path / "policy.yaml"
    source.write_bytes(DATA)

    with open_confined_file(source) as (stream, before):
        assert not changed_since(before, stream.fileno())
        with source.open("ab") as writer:
            writer.write(b"extra\n")
        assert changed_since(before, stream.fileno())


def test_open_confined_file_fails_closed_without_platform_support(tmp_path, index, monkeypatch):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) - {os.open})
    probe = _probe(index)

    with pytest.raises(ValueError, match="unavailable on this platform"), open_confined_file(source):
        pass
    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert _lines(probe, source) == b""
    assert probe.ctx.stats.errors == ["test.reader: secure file access is unavailable on this platform"]
    assert probe.ctx.stats.warnings == [
        "test.reader: offline input could not be read (secure file access is unavailable on this platform)"
    ]

    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) | {os.open})
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(ValueError, match="unavailable on this platform"), open_confined_file(source):
        pass


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="descriptor table is not observable")
def test_open_confined_file_releases_descriptors_on_every_path(tmp_path, index):
    regular = tmp_path / "records.jsonl"
    regular.write_bytes(DATA)
    link = tmp_path / "link.jsonl"
    link.symlink_to(regular)
    probe = _probe(index)

    gc.collect()
    before = set(os.listdir("/proc/self/fd"))
    assert probe._read_offline_bytes(regular, probe._offline_budget()) == DATA
    assert _lines(probe, regular) == DATA
    assert probe._read_offline_bytes(link) is None
    assert _lines(probe, link) == b""
    assert probe._read_offline_bytes(tmp_path) is None
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo.jsonl"
        os.mkfifo(fifo)
        assert _lines(probe, fifo) == b""
    with pytest.raises(OSError):
        read_policy_text(tmp_path / "missing.yaml")
    gc.collect()

    assert set(os.listdir("/proc/self/fd")) == before


def test_readers_count_a_file_removed_after_the_walk_as_unscanned(tmp_path, index):
    # A file that vanished between the walk and the open is neither a link nor a
    # permission problem.
    probe = _probe(index)
    gone = tmp_path / "gone.jsonl"

    assert probe._read_offline_bytes(gone, probe._offline_budget()) is None
    assert _lines(probe, gone) == b""
    assert probe.ctx.stats.incomplete_reasons == {"unscanned-input": 2}


def test_readers_count_the_spent_aggregate_budget_as_an_analysis_limit(tmp_path, index):
    # Only a file over the per-file cap is an oversize file; a small file the spent
    # aggregate budget turns away is a limit the scan hit, in both readers and
    # with or without a budget.
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_bytes(DATA)
    second.write_bytes(DATA)
    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    budget = probe._offline_budget()
    assert probe._read_offline_bytes(first, budget) == DATA
    assert probe._read_offline_bytes(second, budget) is None
    assert probe.ctx.stats.incomplete_reasons == {"analysis-limit": 1}

    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    assert probe._read_offline_bytes(first) == DATA
    assert probe._read_offline_bytes(second) is None
    assert probe.ctx.stats.errors == ["test.reader: offline input exceeds the byte limit"]
    assert probe.ctx.stats.incomplete_reasons == {"analysis-limit": 1}

    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)
    assert probe._read_offline_bytes(first) is None
    assert probe.ctx.stats.incomplete_reasons == {"oversize-file": 1}


def _loaded(probe: _Probe, source: Path) -> list[dict]:
    return list(probe._load_offline_file(source, probe._offline_budget()))


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        ("invalid.json", "{not json", {"unparsed-input": 1}),
        ("error.json", '{"error": {"code": 403, "status": "PERMISSION_DENIED"}}', {"upstream-error": 1}),
        ("error.csv", "ok,error\nfalse,missing_scope\n", {"upstream-error": 1}),
        ("paged.json", '{"items": [{"id": "a"}], "next_page": "abc"}', {"unscanned-input": 1}),
        ("paged.jsonl", '{"items": [{"id": "a"}], "nextPageToken": "abc"}\n', {"unscanned-input": 1}),
    ],
    ids=["invalid-json", "provider-error-envelope", "provider-error-csv-row", "next-page", "next-page-jsonl"],
)
def test_parse_stage_diagnostics_name_their_own_category(tmp_path, index, name, text, expected):
    # Issue #264 review: one reason for the whole parse reporter filed provider errors and
    # uncollected pages as syntax errors. A provider error captured in an export is
    # upstream-error, as cloud.gcp counts the same envelope live; a next page the export
    # never collected is unscanned input; content that does not parse stays unparsed-input.
    source = tmp_path / name
    source.write_text(text)
    probe = _probe(index)

    _loaded(probe, source)

    assert probe.ctx.stats.incomplete_reasons == expected


def test_limits_that_end_an_export_are_not_counted_as_syntax_errors(tmp_path, index, monkeypatch):
    # Issue #264 review: "no records were read before <limit>" blames the limit, not the
    # data, and the YAML parser's resource limits are limits too; both were analysis-limit
    # before the parse reporter was given one reason, and are again.
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)
    assert _loaded(probe, source) == []
    assert probe.ctx.stats.incomplete_reasons == {"oversize-file": 1, "analysis-limit": 1}

    from shadowscan.connectors import offline
    from shadowscan.utils.safe_yaml import YAMLResourceLimitError

    def bomb(text: str) -> None:
        raise YAMLResourceLimitError("alias limit")

    monkeypatch.setattr(offline, "strict_bounded_safe_load", bomb)
    export = tmp_path / "records.yaml"
    export.write_text("records: []\n")
    probe = _probe(index)
    assert _loaded(probe, export) == []
    assert probe.ctx.stats.errors == ["test.reader: YAML safety limit exceeded"]
    assert probe.ctx.stats.incomplete_reasons == {"analysis-limit": 1}


def test_the_walk_counts_a_symlink_as_a_link_and_a_fifo_as_unscanned(tmp_path, index):
    exports = tmp_path / "exports"
    exports.mkdir()
    (exports / "records.jsonl").write_bytes(DATA)
    (exports / "linked.jsonl").symlink_to(exports / "records.jsonl")
    if hasattr(os, "mkfifo"):
        os.mkfifo(exports / "pipe.jsonl")
    probe = _probe(index)

    assert [path.name for path in probe._offline_files(str(exports))] == ["records.jsonl"]
    expected = {"unresolved-link": 1}
    if hasattr(os, "mkfifo"):
        expected["unscanned-input"] = 1
    assert probe.ctx.stats.incomplete_reasons == expected


def test_a_missing_input_root_is_not_reported_as_a_link(tmp_path, index):
    probe = _probe(index)

    assert list(probe._offline_files(str(tmp_path / "exprots" / "slack.json"))) == []
    assert probe.ctx.stats.errors == ["test.reader: offline input is missing, inaccessible, or a symlink"]
    assert probe.ctx.stats.incomplete_reasons == {"unscanned-input": 1}

    link = tmp_path / "linked"
    link.symlink_to(tmp_path, target_is_directory=True)
    probe = _probe(index)
    assert list(probe._offline_files(str(link))) == []
    assert probe.ctx.stats.incomplete_reasons == {"unresolved-link": 1}
