"""Per-input execution budgets, and built-in patterns that compile outside them.

:mod:`shadowscan.signatures.matcher` opens a budget for each input
(``SignatureIndex.scan_budget``) and charges every signature operation on it
to that budget. The loader defers compiling the built-in packs' patterns to
their first use (``Signal.defer``); that compilation is not the input's work
and is given back to its budget. This module imports neither of them, so the
loader can create deferred patterns without importing the matcher, which
imports the loader.
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from typing import Any

import regex


class _ScanBudget:
    """The execution budget of one input: a CPU allowance and an absolute wall-clock cap."""

    __slots__ = (
        "cpu_deadline",
        "cpu_seconds",
        "cpu_started",
        "outer",
        "wall_deadline",
        "wall_seconds",
        "wall_started",
    )

    def __init__(self, cpu_seconds: float, wall_seconds: float, outer: _ScanBudget | None) -> None:
        self.cpu_seconds, self.wall_seconds = cpu_seconds, wall_seconds
        self.cpu_started, self.wall_started = time.thread_time(), time.monotonic()
        self.cpu_deadline = self.cpu_started + cpu_seconds
        self.wall_deadline = self.wall_started + wall_seconds
        self.outer = outer
        if outer is not None:
            # A nested budget never outlives the one it runs under; the
            # diagnostic then describes the budget that actually ended it.
            if outer.cpu_deadline < self.cpu_deadline:
                self.cpu_deadline, self.cpu_seconds, self.cpu_started = (
                    outer.cpu_deadline,
                    outer.cpu_seconds,
                    outer.cpu_started,
                )
            if outer.wall_deadline < self.wall_deadline:
                self.wall_deadline, self.wall_seconds, self.wall_started = (
                    outer.wall_deadline,
                    outer.wall_seconds,
                    outer.wall_started,
                )

    def remaining(self) -> float:
        """Seconds left: the smaller of the CPU allowance and the wall cap."""
        return min(self.cpu_deadline - time.thread_time(), self.wall_deadline - time.monotonic())

    def exhausted(self) -> str:
        """Describe the spent budget for a diagnostic (static text, nothing from the input)."""
        cpu = time.thread_time() - self.cpu_started
        wall = time.monotonic() - self.wall_started
        return (
            f"signature matching exceeded the input execution budget (cpu {cpu:.2f}s of "
            f"{self.cpu_seconds:.2f}s, wall {wall:.2f}s of {self.wall_seconds:.2f}s)"
        )

    def credit(self, cpu: float, wall: float) -> None:
        """Give back time spent on work that is not the input's, here and in every enclosing budget.

        The window moves, so a later diagnostic still measures only the input's work.
        """
        budget: _ScanBudget | None = self
        while budget is not None:
            budget.cpu_started += cpu
            budget.cpu_deadline += cpu
            budget.wall_started += wall
            budget.wall_deadline += wall
            budget = budget.outer

    def extend_cpu(self, cpu: float) -> None:
        """Give this budget back CPU time spent on work that was not its input's.

        Unlike ``credit``, which returns time that was no budget's work to every
        enclosing budget, this returns CPU time that was still this scan's work
        (``matcher.separate_budget``) to this budget only. The CPU window moves, so
        a later diagnostic still measures only the input's work, never past an
        enclosing budget's CPU deadline. The wall deadline does not move: it
        carries the walker's clamp to the connector deadline (``wall_seconds``),
        which no allowance may pass.
        """
        self.cpu_started += cpu
        self.cpu_deadline += cpu
        if self.outer is not None:
            self.cpu_deadline = min(self.cpu_deadline, self.outer.cpu_deadline)


_SCAN_BUDGET: ContextVar[_ScanBudget | None] = ContextVar("signature_scan_budget", default=None)


class DeferredPattern:
    """A built-in signal pattern compiled by its first use, which is not charged for compiling it.

    Compiling every built-in pattern with the bounded engine cost 0.3 to 0.45 s of CPU per process
    on the measured runner, before the first file was read. The literal prefilter then runs only
    the patterns whose required literals occur in a text: a three-file staged scan executed 11 of
    about 1,600 and the 24-file sample repository 151. ``python -m shadowscan.signatures.validate``,
    a release gate, compiles every built-in pattern and rejects one that matches the empty string,
    so deferring the shipped packs skips no check that they can fail. Organization packs are not
    deferred: they are still compiled and checked when they load.

    Eager compilation happened before any input's budget started, so the time spent here is
    credited back to the active budget (``_ScanBudget.credit``) and the input that first needs a
    pattern has the same allowance as before. ``pattern`` is the source and compiles nothing;
    every other public attribute is the compiled pattern's, compiled with ``Signal.compile``'s flags.
    """

    __slots__ = ("_compiled", "_flags", "pattern")

    def __init__(self, pattern: str, flags: int) -> None:
        self.pattern = pattern
        self._flags = flags
        self._compiled: Any = None

    def __reduce__(self) -> tuple[Any, ...]:
        # A plugin worker receives the source and compiles what its own inputs need.
        return (DeferredPattern, (self.pattern, self._flags))

    def compiled(self) -> Any:
        """The compiled pattern, compiling it now if no earlier use did."""
        compiled = self._compiled
        if compiled is None:
            cpu, wall = time.thread_time(), time.monotonic()
            # Concurrent first uses may both compile; the programs are identical and either is kept.
            compiled = self._compiled = regex.compile(self.pattern, self._flags)
            budget = _SCAN_BUDGET.get()
            if budget is not None:
                budget.credit(time.thread_time() - cpu, time.monotonic() - wall)
        return compiled

    def __getattr__(self, name: str) -> Any:
        # Only called for names outside the slots. Private and special names are not the
        # pattern's API (copy and pickle probe for them) and must not compile it.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.compiled(), name)


def ready(rx: Any) -> Any:
    """``rx`` compiled, before an execution allowance starts timing it (see ``DeferredPattern``)."""
    return rx.compiled() if isinstance(rx, DeferredPattern) else rx
