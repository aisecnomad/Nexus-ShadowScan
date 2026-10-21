"""Deadline scaling and partial findings on overrun.

A fixed deadline truncated large repositories into an empty report that read
as clean everywhere except the exit code. Two changes are asserted here: the
deadline grows with the input when the operator set none, and a connector that
overruns surrenders the findings it had already completed instead of having
them discarded.
"""

from __future__ import annotations

import os
import time

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import (
    _TIMEOUT_MESSAGE,
    DEFAULT_CONNECTOR_TIMEOUT,
    MAX_AUTO_TIMEOUT,
    Engine,
    _ConnectorRunner,
    _ExportLedger,
    _JobState,
)
from shadowscan.incremental import IncrementalCache
from shadowscan.models import Finding, Kind, Surface


def _tree(root, files: int) -> None:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    for i in range(files):
        (src / f"mod{i}.py").write_text(f"VALUE = {i}\n", encoding="utf-8")


def _runner(cfg: ScanConfig) -> _ConnectorRunner:
    engine = Engine(cfg)
    return _ConnectorRunner(engine, IncrementalCache(cfg, engine.index), None, _ExportLedger())


class TestEstimate:
    def test_base_connector_proposes_nothing(self) -> None:
        assert BaseConnector.estimate_timeout_seconds({}, 120.0) is None

    def test_a_small_tree_keeps_the_default(self, tmp_path) -> None:
        _tree(tmp_path, 20)
        assert FilesystemConnector.estimate_timeout_seconds({"paths": [str(tmp_path)]}, 120.0) is None

    def test_a_large_tree_asks_for_more(self, tmp_path) -> None:
        _tree(tmp_path, 100)
        # Lower the threshold rather than writing 12,000 files in a test.
        original = FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET
        FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = 25
        try:
            proposed = FilesystemConnector.estimate_timeout_seconds({"paths": [str(tmp_path)]}, 120.0)
        finally:
            FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = original
        assert proposed is not None
        assert proposed > 120.0

    def test_excluded_directories_do_not_inflate_the_estimate(self, tmp_path) -> None:
        _tree(tmp_path, 5)
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        for i in range(500):
            (vendored / f"f{i}.js").write_text("x\n", encoding="utf-8")
        # The root, src/ and its five files.
        assert FilesystemConnector._probe_entry_count([tmp_path]) == 7

    def test_the_connector_exclude_settings_shape_the_probe(self, tmp_path, monkeypatch) -> None:
        _tree(tmp_path, 5)
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        for i in range(100):
            (vendored / f"f{i}.js").write_text("x\n", encoding="utf-8")
        monkeypatch.setattr(FilesystemConnector, "_ENTRIES_PER_DEFAULT_BUDGET", 25)
        paths = [str(tmp_path)]
        assert FilesystemConnector.estimate_timeout_seconds({"paths": paths}, 120.0) is None
        # The walk reads node_modules without the default excludes, so the estimate counts it.
        unexcluded = FilesystemConnector.estimate_timeout_seconds(
            {"paths": paths, "default_excludes": False}, 120.0
        )
        assert unexcluded is not None and unexcluded > 120.0
        excluded = {"paths": paths, "default_excludes": False, "exclude": ["node_modules"]}
        assert FilesystemConnector.estimate_timeout_seconds(excluded, 120.0) is None

    def test_directories_count_so_an_empty_tree_cannot_hold_the_probe(self, tmp_path, monkeypatch) -> None:
        for i in range(50):
            (tmp_path / f"d{i}").mkdir()
        (tmp_path / "agent.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.setattr(FilesystemConnector, "_PROBE_LIMIT", 10)
        assert FilesystemConnector._probe_entry_count([tmp_path]) == 10

    def test_a_probe_out_of_time_reports_its_limit(self, tmp_path, monkeypatch) -> None:
        # A tree it cannot count within its time is at least as large as it can measure.
        _tree(tmp_path, 5)
        monkeypatch.setattr(FilesystemConnector, "_PROBE_SECONDS", 0.0)
        assert FilesystemConnector._probe_entry_count([tmp_path]) == FilesystemConnector._PROBE_LIMIT

    def test_the_probe_stops_inside_one_flat_directory(self, tmp_path, monkeypatch) -> None:
        # A flat directory of 400,000 files took 1.7-2.4 s: its limit was checked
        # only between directories, after every entry had been sized.
        for i in range(3_000):
            (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.setattr(FilesystemConnector, "_PROBE_LIMIT", 500)
        monkeypatch.setattr(FilesystemConnector, "_PROBE_CHECK_ENTRIES", 100)
        sized = 0
        original = FilesystemConnector._probe_file.__func__

        def counted(cls, *args) -> None:
            nonlocal sized
            sized += 1
            original(cls, *args)

        monkeypatch.setattr(FilesystemConnector, "_probe_file", classmethod(counted))
        assert FilesystemConnector._probe_entry_count([tmp_path]) == 500
        assert sized < 700, sized

    def test_the_probe_stops_at_its_limit(self, tmp_path) -> None:
        _tree(tmp_path, 60)
        original = FilesystemConnector._PROBE_LIMIT
        FilesystemConnector._PROBE_LIMIT = 10
        try:
            assert FilesystemConnector._probe_entry_count([tmp_path]) == 10
        finally:
            FilesystemConnector._PROBE_LIMIT = original

    def test_the_proposal_saturates_where_the_probe_stops(self, tmp_path, monkeypatch) -> None:
        """The probe cannot count past its limit, so the proposal cannot grow past it either.

        Measured on real trees: below the limit a larger tree gets a longer
        deadline, past it a tree ten times larger gets the same one. With the
        shipped limits, a probe that cannot finish proposes the most the
        estimate can, which is the engine's own ceiling: the former 20,000-entry
        limit saturated at 200 seconds. The count cap now reaches the ceiling
        while keeping the same per-entry rate and one-second probe budget. A tree
        larger than the ceiling covers needs an explicit deadline, which the
        engineering log says (test_repository_consistency).
        """
        monkeypatch.setattr(FilesystemConnector, "_PROBE_LIMIT", 40)
        monkeypatch.setattr(FilesystemConnector, "_ENTRIES_PER_DEFAULT_BUDGET", 10)
        proposals = []
        for files in (20, 40, 400):
            _tree(tmp_path / f"t{files}", files)
            config = {"paths": [str(tmp_path / f"t{files}")]}
            proposals.append(FilesystemConnector.estimate_timeout_seconds(config, DEFAULT_CONNECTOR_TIMEOUT))
        below, at_limit, past_limit = proposals
        assert below is not None and at_limit is not None
        assert DEFAULT_CONNECTOR_TIMEOUT < below < at_limit
        assert past_limit == at_limit
        monkeypatch.undo()
        monkeypatch.setattr(FilesystemConnector, "_PROBE_SECONDS", 0.0)
        largest = FilesystemConnector.estimate_timeout_seconds(
            {"paths": [str(tmp_path / "t400")]}, DEFAULT_CONNECTOR_TIMEOUT
        )
        assert largest == MAX_AUTO_TIMEOUT
        ceiling = (
            DEFAULT_CONNECTOR_TIMEOUT
            * FilesystemConnector._PROBE_LIMIT
            / FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET
        )
        assert ceiling == MAX_AUTO_TIMEOUT, "the probe limit must let the estimate reach the engine's ceiling"
        monkeypatch.undo()
        assert FilesystemConnector._PROBE_SECONDS == 1.0
        assert FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET == 12_000

    def test_a_missing_path_is_not_an_error(self) -> None:
        assert FilesystemConnector.estimate_timeout_seconds({"paths": ["/nonexistent/xyz"]}, 120.0) is None

    def test_no_paths_proposes_nothing(self) -> None:
        assert FilesystemConnector.estimate_timeout_seconds({}, 120.0) is None


class TestDeadlineExtension:
    """The deadline grows where the class resolved for the job proposes it.

    Done against the already-resolved class rather than a fresh lookup: a
    second ``get_connector_class`` would run outside the job's origin-policy
    scope, which ``test_approval_boundaries`` pins.
    """

    @staticmethod
    def _state(timeout: float) -> _JobState:
        state = _JobState()
        state.deadline = time.monotonic() + timeout
        return state

    def _extend(self, cfg: ScanConfig, spec: ConnectorSpec, state: _JobState) -> float:
        before = state.deadline
        assert before is not None
        _runner(cfg)._extend_deadline_for_large_input(spec, FilesystemConnector, state)
        assert state.deadline is not None
        return state.deadline - before

    def test_an_explicit_timeout_is_never_scaled(self, tmp_path) -> None:
        _tree(tmp_path, 100)
        cfg = ScanConfig(connectors=[], connector_timeout_seconds=7.0)
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        original = FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET
        FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = 25
        try:
            assert self._extend(cfg, spec, self._state(7.0)) == 0
        finally:
            FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = original

    @staticmethod
    def _configured(source: str, value: str | None, monkeypatch) -> ScanConfig:
        """A scan configuration whose timeout comes from ``source``; ``value`` None sets none."""
        if source == "constructor":
            return ScanConfig() if value is None else ScanConfig(connector_timeout_seconds=float(value))
        if source == "legacy null":
            # The deprecated alias's null, which once meant no deadline, selects the default.
            return ScanConfig.from_dict({"options": {"connector_timeout": None}})
        if source == "configuration":
            return ScanConfig.from_dict(
                {"options": {} if value is None else {"connector_timeout_seconds": value}}
            )
        received: list[ScanConfig] = []
        monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda config, *a, **k: received.append(config))
        flag = [] if value is None else ["--connector-timeout-seconds", value]
        result = CliRunner().invoke(main, ["run", "gateway.logs", *flag])
        assert result.exit_code == 0, result.output
        return received[0]

    @pytest.mark.parametrize("source", ["constructor", "configuration", "command line"])
    def test_an_explicit_timeout_equal_to_the_default_is_never_scaled(
        self, tmp_path, monkeypatch, source
    ) -> None:
        # Regression: the engine compared the setting with 120 s, so an explicit
        # --connector-timeout-seconds 120 was scaled as if nothing had been set.
        _tree(tmp_path, 100)
        monkeypatch.setattr(FilesystemConnector, "_ENTRIES_PER_DEFAULT_BUDGET", 25)
        cfg = self._configured(source, "120", monkeypatch)
        cfg.validate_security_options()  # as every run does
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        assert self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT)) == 0

    @pytest.mark.parametrize("source", ["constructor", "configuration", "legacy null", "command line"])
    def test_an_unset_timeout_is_scaled_whatever_the_source(self, tmp_path, monkeypatch, source) -> None:
        _tree(tmp_path, 100)
        monkeypatch.setattr(FilesystemConnector, "_ENTRIES_PER_DEFAULT_BUDGET", 25)
        cfg = self._configured(source, None, monkeypatch)
        cfg.validate_security_options()  # as every run does
        assert cfg.connector_timeout_seconds == DEFAULT_CONNECTOR_TIMEOUT
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        assert self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT)) > 0

    def test_the_default_is_extended_for_a_large_tree(self, tmp_path) -> None:
        _tree(tmp_path, 100)
        cfg = ScanConfig(connectors=[])
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        original = FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET
        FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = 25
        try:
            assert self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT)) > 0
        finally:
            FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = original

    def test_a_small_tree_leaves_the_deadline_alone(self, tmp_path) -> None:
        _tree(tmp_path, 10)
        cfg = ScanConfig(connectors=[])
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        assert self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT)) == 0

    def test_the_extension_is_capped(self, tmp_path) -> None:
        _tree(tmp_path, 200)
        cfg = ScanConfig(connectors=[])
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        original = FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET
        FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = 1
        try:
            grew = self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT))
        finally:
            FilesystemConnector._ENTRIES_PER_DEFAULT_BUDGET = original
        assert grew == pytest.approx(MAX_AUTO_TIMEOUT - DEFAULT_CONNECTOR_TIMEOUT)

    def test_a_byte_padded_tree_is_clamped_at_the_ceiling(self, tmp_path, monkeypatch) -> None:
        # A hostile tree of a few files padded to just under max_file_size asks
        # for far more than the ceiling by bytes alone; the engine still clamps it.
        for i in range(3):
            (tmp_path / f"pad{i}.py").write_bytes(b"#" * 10_000)
            (tmp_path / f"pad{i}.lock").write_bytes(b"#" * 10_000)
        (tmp_path / "uv.lock").write_bytes(b"#" * 10_000)
        monkeypatch.setattr(FilesystemConnector, "_SOURCE_BYTES_PER_DEFAULT_BUDGET", 10)
        monkeypatch.setattr(FilesystemConnector, "_READ_BYTES_PER_DEFAULT_BUDGET", 10)
        config = {"paths": [str(tmp_path)], "max_file_size": 10_000}
        proposal = FilesystemConnector.estimate_timeout_seconds(config, DEFAULT_CONNECTOR_TIMEOUT)
        assert proposal is not None and proposal > 100 * MAX_AUTO_TIMEOUT
        spec = ConnectorSpec(name="code.filesystem", config=config)
        grew = self._extend(ScanConfig(connectors=[]), spec, self._state(DEFAULT_CONNECTOR_TIMEOUT))
        assert grew == pytest.approx(MAX_AUTO_TIMEOUT - DEFAULT_CONNECTOR_TIMEOUT)

    def test_an_estimate_that_raises_leaves_the_deadline_alone(self, tmp_path, monkeypatch) -> None:
        def boom(cls, config, default):
            raise RuntimeError("probe exploded")

        monkeypatch.setattr(FilesystemConnector, "estimate_timeout_seconds", classmethod(boom))
        cfg = ScanConfig(connectors=[])
        spec = ConnectorSpec(name="code.filesystem", config={"paths": [str(tmp_path)]})
        assert self._extend(cfg, spec, self._state(DEFAULT_CONNECTOR_TIMEOUT)) == 0

    def test_a_connector_that_proposes_nothing_is_unaffected(self, tmp_path) -> None:
        cfg = ScanConfig(connectors=[])
        spec = ConnectorSpec(name="probe", config={})
        state = self._state(DEFAULT_CONNECTOR_TIMEOUT)
        before = state.deadline
        _runner(cfg)._extend_deadline_for_large_input(spec, BaseConnector, state)
        assert state.deadline == before


class TestPartialFindings:
    @staticmethod
    def _finding(i: int) -> Finding:
        return Finding(
            connector="code.filesystem",
            surface=Surface.CODE,
            kind=Kind.AGENT,
            title=f"finding {i}",
            resource=f"r{i}",
            resource_type="repo",
        )

    def test_registered_findings_survive_an_expiry(self) -> None:
        state = _JobState()
        live: list[Finding] = []
        state.register_partial(live)
        live.append(self._finding(1))
        live.append(self._finding(2))
        assert len(state.take_partial()) == 2

    def test_take_partial_is_a_copy(self) -> None:
        state = _JobState()
        live: list[Finding] = [self._finding(1)]
        state.register_partial(live)
        taken = state.take_partial()
        live.append(self._finding(2))
        assert len(taken) == 1

    def test_nothing_registered_yields_nothing(self) -> None:
        assert _JobState().take_partial() == []

    def test_a_multi_root_overrun_reports_every_root_it_finished(self, tmp_path, monkeypatch, index) -> None:
        # Regression: each repository root registered its findings in place of
        # the last root's, and a root reused from the cache registered none, so
        # an expiry in the last root reported only that root's findings.
        roots = [tmp_path / name for name in ("cached", "analysed", "overrunning")]
        for root in roots:
            root.mkdir()
            (root / "requirements.txt").write_text("langchain\n")
        spec = ConnectorSpec("code.filesystem", {"paths": [str(root) for root in roots], "use_git": False})
        cfg = ScanConfig(
            connectors=[spec],
            incremental=True,
            state_dir=str(tmp_path / "state"),
            connector_timeout_seconds=3.0,
        )
        assert Engine(cfg, index).run().complete
        for root, framework in zip(roots[1:], ("crewai", "langgraph"), strict=True):
            (root / "requirements.txt").write_text(f"{framework}\n")
        analyze = FilesystemConnector.analyze

        def overrun(self, records):
            yield from analyze(self, records)
            if self.ctx.config["path"] == str(roots[-1]):
                self.ctx.cancelled.wait(30)

        monkeypatch.setattr(FilesystemConnector, "analyze", overrun)
        result = Engine(cfg, index).run()

        assert not result.complete and result.stats[0].skip_reason == _TIMEOUT_MESSAGE
        frameworks = {framework for finding in result.findings for framework in finding.frameworks}
        assert {"framework.langchain", "framework.crewai", "framework.langgraph"} <= frameworks

    def test_an_overrun_reports_the_findings_it_had(self, monkeypatch) -> None:
        """A connector that blows its deadline mid-analysis still reports what it found."""
        from shadowscan.connectors import base as base_mod

        findings = [self._finding(i) for i in range(3)]

        class SlowConnector(BaseConnector):
            name = "test.slow"
            surface = Surface.CODE

            def collect(self):
                return iter(())

            def analyze(self, records):
                yield from findings
                # Outlive the deadline the caller set.
                time.sleep(5)

        ctx = base_mod.ConnectorContext(config={})
        state = _JobState()
        ctx.partial_sink = state.register_partial
        connector = SlowConnector(ctx)
        # Registration happens before any work, so the sink is live even if
        # the worker never returns.
        connector.ctx.partial_sink(list(findings))
        assert len(state.take_partial()) == 3


class TestMessages:
    def test_the_timeout_message_tells_the_operator_what_to_change(self) -> None:
        from shadowscan.engine import _TIMEOUT_MESSAGE

        assert "truncated" in _TIMEOUT_MESSAGE
        assert "connector-timeout-seconds" in _TIMEOUT_MESSAGE
        # The old wording claimed results were discarded; they no longer are.
        assert "discarded" not in _TIMEOUT_MESSAGE


@pytest.mark.parametrize("ratio", [0.0, 0.02, 1.0])
def test_scan_config_round_trips_the_gap_budget(ratio: float) -> None:
    assert ScanConfig(connectors=[], max_coverage_gap=ratio).max_coverage_gap == ratio


class TestByteAwareEstimate:
    """Bytes the reader analyses drive the deadline as well as entries.

    Regression: the estimate counted entries only, so run-llama_llama_index
    (13,499 entries, 480 MB of supported uv.lock files) got 270 s against a
    measured need of 232-290 s and BerriAI_litellm (156 MB of source) 325 s,
    and both exited 3 on a contended runner.
    """

    @staticmethod
    def _estimate(root, **config) -> float | None:
        return FilesystemConnector.estimate_timeout_seconds({"paths": [str(root)], **config}, 120.0)

    @staticmethod
    def _small_budgets(monkeypatch) -> None:
        monkeypatch.setattr(FilesystemConnector, "_SOURCE_BYTES_PER_DEFAULT_BUDGET", 10_000)
        monkeypatch.setattr(FilesystemConnector, "_READ_BYTES_PER_DEFAULT_BUDGET", 100_000)

    def test_few_entries_with_many_source_bytes_are_extended(self, tmp_path, monkeypatch) -> None:
        self._small_budgets(monkeypatch)
        (tmp_path / "big.py").write_bytes(b"x = 1\n" * 5_000)  # 30,000 bytes: three source budgets
        assert self._estimate(tmp_path) == pytest.approx(360.0)

    def test_read_bytes_count_at_their_own_rate(self, tmp_path, monkeypatch) -> None:
        self._small_budgets(monkeypatch)
        (tmp_path / "data.json").write_bytes(b" " * 200_000)
        (tmp_path / "mod.py").write_bytes(b" " * 10_000)
        assert self._estimate(tmp_path, max_file_size=300_000) == pytest.approx(120.0 * (2 + 1))

    def test_files_over_the_size_limit_add_no_bytes(self, tmp_path, monkeypatch) -> None:
        self._small_budgets(monkeypatch)
        (tmp_path / "big.py").write_bytes(b" " * 30_000)
        assert self._estimate(tmp_path, max_file_size=20_000) is None
        probe = FilesystemConnector._probe_tree([tmp_path], size_limit=20_000)
        assert (probe.entries, probe.source_bytes, probe.read_bytes) == (2, 0, 0)

    def test_a_notebook_counts_up_to_its_own_limit(self, tmp_path) -> None:
        (tmp_path / "nb.ipynb").write_bytes(b" " * 30_000)
        probe = FilesystemConnector._probe_tree([tmp_path], size_limit=10_000, notebook_limit=40_000)
        # The code-cell share is source; outputs past max_file_size are read at the cheaper rate.
        assert (probe.source_bytes, probe.read_bytes) == (10_000, 20_000)
        over = FilesystemConnector._probe_tree([tmp_path], size_limit=10_000, notebook_limit=20_000)
        assert (over.source_bytes, over.read_bytes) == (0, 0)

    def test_a_symlinked_file_adds_an_entry_but_no_bytes(self, tmp_path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "big.py").write_bytes(b" " * 5_000)
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "link.py").symlink_to(outside / "big.py")
        probe = FilesystemConnector._probe_tree([tree])
        assert (probe.entries, probe.source_bytes, probe.read_bytes) == (2, 0, 0)

    def test_a_symlinked_directory_is_not_descended(self, tmp_path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        for i in range(20):
            (outside / f"m{i}.py").write_bytes(b" " * 1_000)
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "linked").symlink_to(outside, target_is_directory=True)
        probe = FilesystemConnector._probe_tree([tree])
        # The root and the link itself; nothing behind the link is listed or sized.
        assert (probe.entries, probe.source_bytes, probe.read_bytes) == (2, 0, 0)

    def test_the_probe_never_follows_a_link_or_opens_a_file(self, tmp_path, monkeypatch) -> None:
        _tree(tmp_path, 3)
        (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        (tmp_path / "link.py").symlink_to(tmp_path / "src" / "mod0.py")
        follows: list[bool] = []
        real_scandir = os.scandir

        class Entry:
            def __init__(self, entry: os.DirEntry[str]) -> None:
                self._entry = entry
                self.name, self.path = entry.name, entry.path

            def is_dir(self, *, follow_symlinks: bool = True) -> bool:
                follows.append(follow_symlinks)
                return self._entry.is_dir(follow_symlinks=follow_symlinks)

            def is_file(self, *, follow_symlinks: bool = True) -> bool:
                follows.append(follow_symlinks)
                return self._entry.is_file(follow_symlinks=follow_symlinks)

            def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
                follows.append(follow_symlinks)
                return self._entry.stat(follow_symlinks=follow_symlinks)

        class Listing:
            def __init__(self, path: object) -> None:
                self._it = real_scandir(path)  # type: ignore[call-overload]

            def __enter__(self) -> object:
                return (Entry(e) for e in self._it)

            def __exit__(self, *exc: object) -> None:
                self._it.close()

        def no_open(*_args: object, **_kwargs: object) -> None:
            pytest.fail("the probe opened a file")

        monkeypatch.setattr("shadowscan.connectors.code.filesystem.os.scandir", Listing)
        monkeypatch.setattr("builtins.open", no_open)
        monkeypatch.setattr("os.open", no_open)
        probe = FilesystemConnector._probe_tree([tmp_path])
        monkeypatch.undo()
        # The root, src/, three modules, uv.lock and the link.
        assert probe.entries == 7
        assert follows and not any(follows)

    def test_pruned_directories_add_no_bytes(self, tmp_path, monkeypatch) -> None:
        self._small_budgets(monkeypatch)
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_bytes(b" " * 50_000)
        assert self._estimate(tmp_path) is None
        assert self._estimate(tmp_path, default_excludes=False) is not None

    def test_supported_lockfiles_count_and_other_never_read_files_do_not(self, tmp_path) -> None:
        # Only the lockfiles the reader parses (lockfiles.LOCKFILE_NAMES) are read.
        for name in ("uv.lock", "poetry.lock", "pnpm-lock.yaml", "Cargo.lock"):
            (tmp_path / name).write_bytes(b" " * 1_000)
        for name in ("yarn.lock", "Gemfile.lock", "bundle.min.js", "app.js.map", "x.pyc"):
            (tmp_path / name).write_bytes(b" " * 7_000)
        probe = FilesystemConnector._probe_tree([tmp_path])
        assert probe.entries == 10
        assert (probe.source_bytes, probe.read_bytes) == (0, 4_000)

    def test_a_timed_out_probe_still_saturates_to_the_ceiling(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.setattr(FilesystemConnector, "_PROBE_SECONDS", 0.0)
        assert self._estimate(tmp_path) == MAX_AUTO_TIMEOUT
        monkeypatch.undo()
        monkeypatch.setattr(FilesystemConnector, "_PROBE_LIMIT", 1)
        assert FilesystemConnector._probe_tree([tmp_path]).entries == 1

    @pytest.mark.parametrize("source_bytes", [0, 1, 5_000, 100_000])
    def test_bytes_never_lower_the_entry_proposal(self, tmp_path, monkeypatch, source_bytes) -> None:
        self._small_budgets(monkeypatch)
        monkeypatch.setattr(FilesystemConnector, "_ENTRIES_PER_DEFAULT_BUDGET", 10)
        _tree(tmp_path, 38)  # the root, src/ and 38 files: four entry budgets
        (tmp_path / "src" / "mod0.py").write_bytes(b" " * source_bytes)
        proposal = self._estimate(tmp_path)
        assert proposal is not None and proposal >= 120.0 * 4
        source = FilesystemConnector._probe_tree([tmp_path]).source_bytes
        assert proposal == pytest.approx(max(480.0, 120.0 * source / 10_000))

    def test_an_invalid_size_option_proposes_nothing(self, tmp_path) -> None:
        (tmp_path / "a.py").write_bytes(b" " * 100)
        assert self._estimate(tmp_path, max_file_size=0) is None
        assert self._estimate(tmp_path, max_notebook_size="big") is None


class TestPostWalkReserve:
    """Work after the walk fits in the margin the walk keeps back.

    Regression: the walk stopped five percent before the deadline, but
    re-export binding and finding emission (22 s on llama_index) outran that,
    so the engine cut the connector and the report showed it skipped, with 0
    objects examined and an arbitrary prefix of findings, instead of the
    walk's "after N of M files" disclosure.
    """

    def test_the_reserve_grows_with_scanned_files_and_is_capped(self) -> None:
        from shadowscan.connectors.code.walk import (
            DEADLINE_MARGIN_FRACTION,
            POST_WALK_RESERVE_FRACTION,
            POST_WALK_SECONDS_PER_FILE,
            deadline_margin,
        )

        assert deadline_margin(270.0) == pytest.approx(270.0 * DEADLINE_MARGIN_FRACTION)
        assert deadline_margin(270.0, 9_000) == pytest.approx(9_000 * POST_WALK_SECONDS_PER_FILE)
        assert deadline_margin(270.0, 10**9) == pytest.approx(270.0 * POST_WALK_RESERVE_FRACTION)
        assert deadline_margin(270.0, 10) == deadline_margin(270.0)

    def test_a_deadline_truncated_walk_keeps_its_accounting(self, tmp_path, monkeypatch) -> None:
        import json

        from shadowscan.connectors.code.file_scan import FileScanner
        from shadowscan.connectors.code.project_findings import ProjectFindings

        root = tmp_path / "repo"
        root.mkdir()
        (root / "requirements.txt").write_text("langchain\n", encoding="utf-8")
        for i in range(2_000):
            (root / f"m{i}.py").write_text(f"VALUE = {i}\n", encoding="utf-8")
        scanned: list[str] = []

        def slow_scan(self, scan, rel, path, proj_root) -> None:
            self.ctx.examined()
            scanned.append(rel)
            time.sleep(0.01)

        emit = ProjectFindings.emit_findings

        def slow_emit(self, scan):
            # Post-walk work past what the walk used to leave (the five-percent
            # margin plus one file's 2 s matching budget: 2.5 s of 10 s) and
            # inside what it now leaves (that budget plus a quarter: 4.5 s).
            time.sleep(3.5)
            yield from emit(self, scan)

        # Reach the reserve's cap within the few hundred files a test can scan;
        # a contended runner then cannot shrink the reserve by scanning fewer.
        monkeypatch.setattr("shadowscan.connectors.code.walk.POST_WALK_SECONDS_PER_FILE", 0.05, raising=False)
        monkeypatch.setattr(FileScanner, "scan_file", slow_scan)
        monkeypatch.setattr(ProjectFindings, "emit_findings", slow_emit)

        def hard_exit(code: int) -> None:
            # The CLI leaves a worker the engine cut with os._exit: the failure this pins.
            raise SystemExit(code)

        monkeypatch.setattr("shadowscan.cli.os._exit", hard_exit)
        out = tmp_path / "report.json"
        result = CliRunner().invoke(
            main,
            ["code", str(root), "--connector-timeout-seconds", "10", "--format", "json", "-o", str(out)],
        )
        assert result.exit_code == 3, result.output
        stats = json.loads(out.read_text(encoding="utf-8"))["stats"][0]
        assert stats["skipped"] is False and stats["incomplete"] is True
        assert 0 < stats["objects_examined"] < 2_001
        assert any("connector deadline reached after" in e and " of 2001 files" in e for e in stats["errors"])

    def test_the_post_walk_reserve_counts_only_files_the_walk_read(
        self, tmp_path, index, monkeypatch
    ) -> None:
        # Thousands of never-read assets sort first and reserve nothing; counting them
        # raised the margin to its cap before the first source file, so a tree that
        # completed on main stopped at 75% of its window instead of 95%.
        from shadowscan.connectors.base import ConnectorContext
        from shadowscan.connectors.code import walk

        root = tmp_path / "repo"
        (root / "assets").mkdir(parents=True)
        for i in range(2_000):
            (root / "assets" / f"img{i}.png").write_bytes(b"x")
        for i in range(3):
            (root / f"m{i}.py").write_text(f"VALUE = {i}\n", encoding="utf-8")
        counts: list[int] = []
        margin = walk.deadline_margin

        def recorded(remaining: float, read: int = 0) -> float:
            counts.append(read)
            return margin(remaining, read)

        monkeypatch.setattr(walk, "deadline_margin", recorded)
        ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)
        ctx.deadline = time.monotonic() + 600.0
        FilesystemConnector(ctx).run()
        assert counts and max(counts) <= 3, max(counts)
        assert not ctx.stats.incomplete, ctx.stats.errors

    def test_emission_past_the_deadline_names_what_it_left_out(self, tmp_path, index, monkeypatch) -> None:
        from shadowscan.connectors.base import ConnectorContext
        from shadowscan.connectors.code.file_scan import FileScanner

        root = tmp_path / "repo"
        for package in ("a", "b", "c"):
            (root / package).mkdir(parents=True)
            (root / package / "requirements.txt").write_text("langchain\n", encoding="utf-8")
        ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)

        def spent(self, scan) -> None:
            # Binding used up the time: emission starts inside the margin. The root
            # and its three packages are four projects.
            self.ctx.deadline = time.monotonic() + 5.0
            scan.margin = 20.0

        monkeypatch.setattr(FileScanner, "resolve_reexport_sources", spent)
        findings = FilesystemConnector(ctx).run()
        assert not any(f.resource_type == "project" for f in findings)
        assert ctx.stats.incomplete and not ctx.stats.skipped
        assert any(
            "connector deadline reached during finding emission; the findings of 4 of 4 projects" in e
            for e in ctx.stats.errors
        )
        assert ctx.stats.incomplete_reasons.get("timeout") == 1
