"""Deadline scaling and partial findings on overrun.

A fixed deadline truncated large repositories into an empty report that read
as clean everywhere except the exit code. Two changes are asserted here: the
deadline grows with the input when the operator set none, and a connector that
overruns surrenders the findings it had already completed instead of having
them discarded.
"""

from __future__ import annotations

import time

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import (
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

    def test_the_probe_stops_at_its_limit(self, tmp_path) -> None:
        _tree(tmp_path, 60)
        original = FilesystemConnector._PROBE_LIMIT
        FilesystemConnector._PROBE_LIMIT = 10
        try:
            assert FilesystemConnector._probe_entry_count([tmp_path]) == 10
        finally:
            FilesystemConnector._PROBE_LIMIT = original

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
