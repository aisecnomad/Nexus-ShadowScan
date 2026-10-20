"""Built-in patterns compile on first use, outside the budget of the input that needs them.

Compiling every built-in pattern took 0.3 to 0.45 s of each process on the
measured runner; a staged pre-commit scan runs a few of them. Deferral must not
change a result, charge an input's budget, accept an organization pack that the
eager loader rejects, or let a pattern that fails to compile look like no match.
"""

from __future__ import annotations

import copy
import pickle
import time
from pathlib import Path

import pytest
import regex
import yaml

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.signatures.budget import _SCAN_BUDGET, DeferredPattern
from shadowscan.signatures.loader import Signal, Signature, SignaturePackError, load_signatures
from shadowscan.signatures.matcher import MatchTimeoutError, SignatureIndex, _search, get_index

SAMPLE_REPO = Path(__file__).parents[1] / "fixtures" / "sample_repo"


def _patterns(index: SignatureIndex) -> list[object]:
    return [
        rx for sig in index.signatures.values() for signal in sig.signals for rx in signal.bounded_compiled
    ]


def _scan(index: SignatureIndex) -> list[tuple[str, str]]:
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(SAMPLE_REPO)})]), index
    ).run()
    assert result.complete, result.stats
    return sorted((finding.id, finding.title) for finding in result.findings)


def test_builtin_patterns_compile_on_first_use_with_unchanged_results() -> None:
    deferred = SignatureIndex(load_signatures(defer_builtin=True))
    patterns = _patterns(deferred)
    assert patterns and all(isinstance(rx, DeferredPattern) and rx._compiled is None for rx in patterns)
    eager = SignatureIndex(load_signatures())
    assert all(isinstance(rx, regex.Pattern) for rx in _patterns(eager))
    assert deferred.fingerprint() == eager.fingerprint()
    assert _scan(deferred) == _scan(eager)
    compiled = [rx for rx in patterns if rx._compiled is not None]
    # The literal prefilter skips most patterns: the 24-file sample compiled about a tenth.
    assert 0 < len(compiled) < len(patterns) / 4
    assert all(rx._compiled.pattern == rx.pattern for rx in compiled)


def test_the_process_index_defers_only_the_builtin_packs(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    signal = {"type": "import", "patterns": [r"^import acme_agent\b"]}
    pack.write_text(
        yaml.safe_dump({"signatures": [{"id": "org.acme", "category": "framework", "signals": [signal]}]})
    )
    index = get_index(extra_dirs=[str(tmp_path)])
    custom = index.signatures["org.acme"].signals[0].bounded_compiled
    assert len(custom) == 1 and isinstance(custom[0], regex.Pattern)
    assert isinstance(_patterns(get_index(reload=True))[0], DeferredPattern)
    # An organization pack is compiled and checked as it loads, deferral or not.
    for broken in ("(", "a*"):
        signal["patterns"] = [broken]
        pack.write_text(
            yaml.safe_dump({"signatures": [{"id": "org.acme", "category": "framework", "signals": [signal]}]})
        )
        with pytest.raises(SignaturePackError):
            load_signatures([tmp_path], defer_builtin=True)
        with pytest.raises(SignaturePackError):
            get_index(extra_dirs=[str(tmp_path)])


def test_compiling_is_credited_to_the_input_budget(
    monkeypatch: pytest.MonkeyPatch, index: SignatureIndex
) -> None:
    real_compile = regex.compile

    def slow_compile(pattern: str, flags: int = 0) -> regex.Pattern[str]:
        # Spend CPU and wall time well past the budget below, as a slow machine compiling many
        # patterns for one input would.
        stop = time.thread_time() + 0.2
        while time.thread_time() < stop:
            pass
        return real_compile(pattern, flags)

    monkeypatch.setattr("shadowscan.signatures.matcher.regex.compile", slow_compile)
    rx = DeferredPattern(r"\bacme_agent\b", regex.MULTILINE | regex.VERSION0)
    with index.scan_budget(seconds=0.05, wall_seconds=0.1):
        assert _search(rx, "import acme_agent", "test") is not None
        assert rx._compiled is not None
    # The input's own work is still bounded: the budget was not lifted, only given back.
    with pytest.raises(MatchTimeoutError, match="budget"), index.scan_budget(seconds=0.05, wall_seconds=0.1):
        stop = time.thread_time() + 0.2
        while time.thread_time() < stop:
            pass
        _search(rx, "import acme_agent", "test")


def test_nested_budgets_are_credited_together(index: SignatureIndex) -> None:
    with index.scan_budget(seconds=5):
        outer = _SCAN_BUDGET.get()
        with index.scan_budget(seconds=1):
            inner = _SCAN_BUDGET.get()
            assert inner is not None and outer is not None and inner.outer is outer
            windows = [
                (b.cpu_started, b.cpu_deadline, b.wall_started, b.wall_deadline) for b in (inner, outer)
            ]
            inner.credit(0.5, 0.25)
            for budget, (cpu_started, cpu_deadline, wall_started, wall_deadline) in zip(
                (inner, outer), windows, strict=True
            ):
                # The window moves: the deadline and the start of what counts as the input's work.
                assert budget.cpu_started == pytest.approx(cpu_started + 0.5)
                assert budget.cpu_deadline == pytest.approx(cpu_deadline + 0.5)
                assert budget.wall_started == pytest.approx(wall_started + 0.25)
                assert budget.wall_deadline == pytest.approx(wall_deadline + 0.25)


def test_deferred_patterns_survive_pickle_and_copy_uncompiled() -> None:
    rx = DeferredPattern(r"(?i)\bacme\b", regex.MULTILINE | regex.VERSION0)
    for clone in (pickle.loads(pickle.dumps(rx)), copy.deepcopy(rx), copy.copy(rx)):
        assert isinstance(clone, DeferredPattern) and clone._compiled is None
        assert clone.pattern == rx.pattern
    assert rx._compiled is None
    assert rx.flags == regex.compile(rx.pattern, regex.MULTILINE | regex.VERSION0).flags
    assert [m.group(0) for m in rx.finditer("ACME acme")] == ["ACME", "acme"]
    with pytest.raises(AttributeError):
        rx._missing  # noqa: B018 - private names are never forwarded to the compiled pattern


def test_a_pattern_that_cannot_compile_leaves_the_scan_incomplete(tmp_path: Path) -> None:
    signal = Signal(type="code", weight=0.9, patterns=[r"\bAcmeAgent\("])
    signal.bounded_compiled = [DeferredPattern(r"\bAcmeAgent\((", regex.MULTILINE | regex.VERSION0)]
    broken = Signature(id="org.broken", name="Broken", category="framework", signals=[signal])
    index = SignatureIndex([*load_signatures(defer_builtin=True), broken])
    (tmp_path / "agent.py").write_text("agent = AcmeAgent(role='x')\n")
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path)})]), index
    ).run()
    assert not result.complete
    assert any(
        "agent.py" in error and "incomplete" in error for stats in result.stats for error in stats.errors
    )
