"""Per-run state records and synchronized ledgers used by the scan engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Event, Lock
from typing import Any

from shadowscan.config import ConnectorSpec
from shadowscan.models import Surface

_Job = tuple[int, ConnectorSpec]  # (1-based configuration ordinal, connector)


@dataclass
class _JobState:
    started_at: str | None = None
    deadline: float | None = None
    completed_at: float | None = None
    cancelled: Event = field(default_factory=Event)
    publication_lock: Lock = field(default_factory=Lock)
    isolated_process: bool = False
    kill_process: Callable[[], None] | None = None

    @property
    def supervision_deadline(self) -> float | None:
        if self.deadline is None:
            return None
        # The process runner enforces the original deadline, including IPC.
        # Retain a last-resort parent guard while allowing bounded TERM/KILL
        # cleanup to finish before treating its supervision thread as abandoned.
        return self.deadline + (2.0 if self.isolated_process else 0.0)


@dataclass
class _RegistryOutcome:
    """What one post-process pass learned about vendor registries, for ``run`` to report."""

    # Malformed records: an incomplete engine.registries entry.
    warnings: list[str] = field(default_factory=list)
    # Trusted registries without records: advisory engine.inventory warnings.
    inventory_warnings: list[str] = field(default_factory=list)
    # Approved records of trusted registries: one inventory item each.
    approval_entries: int = 0
    # MCP registry snapshots that failed to load or match: an incomplete engine.mcp-registry entry.
    mcp_registry_errors: list[str] = field(default_factory=list)


class _ExportLedger:
    """Record-export manifest entries reported by connector workers of one run."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: list[dict[str, Any]] = []

    def record(self, state: _JobState, entry: dict[str, Any]) -> None:
        with self._lock:
            if not state.cancelled.is_set():
                self._entries.append(entry)

    def entries(self, jobs: list[_Job], timed_out: set[int]) -> list[dict[str, Any]]:
        """Replace anything a timed-out connector reported with an explicit failure entry."""
        with self._lock:
            entries = [entry for entry in self._entries if entry["config_ordinal"] not in timed_out]
            for number, spec in jobs:
                if number in timed_out:
                    entries.append(
                        {
                            "config_ordinal": number,
                            "part": f"{number:04d}",
                            "connector": spec.name,
                            "label": spec.label,
                            "filename": None,
                            "complete": False,
                            "exported": False,
                        }
                    )
            return entries


class _ScopeLedger:
    """Live collection scope records reported by connector workers of one run, by configuration ordinal.

    A cancelled job reports nothing, and ``records`` drops what a timed-out job reported:
    its findings are discarded, so its scope must not be attested either.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[int, dict[str, Any] | None] = {}
        self._surfaces: dict[int, Surface] = {}

    def declare_surface(self, number: int, surface: Surface) -> None:
        """Remember a worker's already-resolved class contract without importing it again."""
        with self._lock:
            self._surfaces[number] = surface

    def surfaces(self) -> dict[int, Surface]:
        """Declared surfaces, including failed collections; these do not attest coverage."""
        with self._lock:
            return dict(self._surfaces)

    def record(self, state: _JobState, number: int, record: dict[str, Any]) -> None:
        with self._lock:
            if state.cancelled.is_set():
                return
            # One record per configured entry; a second report attests nothing.
            self._records[number] = None if number in self._records else record

    def records(self, timed_out: set[int]) -> dict[int, dict[str, Any]]:
        with self._lock:
            return {
                number: record
                for number, record in self._records.items()
                if record is not None and number not in timed_out
            }
