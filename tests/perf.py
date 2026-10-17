"""Timing helpers for the performance guards, robust to a busy machine.

The guards exist to catch algorithmic blow-up: a pattern that goes quadratic,
a sanitizer that rescans the same line per token. Several of them measured
*wall* time, which answers a different question — it includes every other
process competing for the core — so under a parallel test run they failed on
code that was perfectly linear. One was reproducibly flaky under load and
passed in isolation.

:func:`assert_cpu_budget` measures CPU time instead. Algorithmic cost is CPU-bound,
so this is both the stricter and the more stable measurement: contention no
longer inflates it, while a genuine blow-up still shows up in full.

Two further defences keep a slow or throttled runner from failing honest code:

* the budget is scaled by :func:`speed_factor`, calibrated once against a
  fixed reference workload, so a runner half the speed of a developer laptop
  gets twice the allowance without the test being loosened for everyone;
* a guard that trips is retried once, since a single scheduling stall should
  not fail a build. A real regression fails both attempts.

Use :func:`wall_budget` (or :func:`load_factor`) only where elapsed real time
*is* the thing under test — an IO deadline, a timeout, a preemption. Those
scale by load rather than by raw machine speed, since contention is exactly
what inflates them.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

T = TypeVar("T")

#: Reference workload cost on the machine the budgets were written for.
_REFERENCE_SECONDS = 0.020
_speed_factor: float | None = None


def _reference_workload() -> None:
    total = 0
    for i in range(200_000):
        total += i * i
    assert total


def speed_factor() -> float:
    """How much slower this machine is than the one the budgets assume.

    Measured once per process and clamped: a factor below 1 never tightens a
    budget (a fast machine must not make the guards stricter than written),
    and the upper clamp stops a pathologically slow runner from making a
    guard meaningless.
    """
    global _speed_factor
    if _speed_factor is None:
        started = time.process_time()
        _reference_workload()
        measured = time.process_time() - started
        _speed_factor = min(8.0, max(1.0, measured / _REFERENCE_SECONDS))
    return _speed_factor


def cpu_seconds(work: Callable[[], T]) -> tuple[T, float]:
    """Run *work* and return its result with the CPU time it consumed."""
    started = time.process_time()
    result = work()
    return result, time.process_time() - started


def assert_cpu_budget(work: Callable[[], T], budget: float, what: str = "operation") -> T:
    """Run *work*, failing if it costs more than *budget* CPU seconds.

    Retried once: a single scheduling stall or GC pause should not fail a
    build, while a genuine regression exceeds the budget both times.
    """
    allowance = budget * speed_factor()
    result, spent = cpu_seconds(work)
    if spent <= allowance:
        return result
    result, retry = cpu_seconds(work)
    if retry > allowance:
        raise AssertionError(
            f"{what} used {retry:.3f}s CPU on retry (first attempt {spent:.3f}s), "
            f"over the {allowance:.3f}s budget ({budget:.3f}s x{speed_factor():.1f} for this machine). "
            "This is an algorithmic cost, not contention: CPU time excludes other processes."
        )
    return result


def load_factor() -> float:
    """How much slower *wall* time runs here right now, machine and load together.

    :func:`speed_factor` measures CPU time, which is the point for an
    algorithmic budget and precisely why it cannot calibrate a wall one:
    contention does not inflate CPU time, so a busy machine still reports 1.0
    and a wall assertion fails anyway. This measures the same reference
    workload by the clock, so it rises with the load.

    Measured fresh on every call rather than cached, because load varies
    across a run; the reference workload costs about 20ms.
    """
    started = time.perf_counter()
    _reference_workload()
    measured = time.perf_counter() - started
    return min(16.0, max(1.0, measured / _REFERENCE_SECONDS))


@contextmanager
def wall_budget(budget: float, what: str = "operation") -> Iterator[None]:
    """Assert elapsed *real* time, for a deadline or timeout under test.

    Only for cases where real time is the subject. Everything measuring
    algorithmic cost belongs in :func:`assert_cpu_budget`, which contention
    cannot inflate.
    """
    started = time.perf_counter()
    yield
    elapsed = time.perf_counter() - started
    factor = load_factor()
    allowance = budget * factor
    if elapsed > allowance:
        raise AssertionError(
            f"{what} took {elapsed:.3f}s, over the {allowance:.3f}s wall budget "
            f"({budget:.3f}s x{factor:.1f} for this machine under its current load)."
        )
