"""Candidate public API for the 1.0 compatibility boundary.

Use :func:`scan` with an explicit configuration. Internal modules remain
available, but are outside this deliberately small compatibility surface.
The package is still alpha; see ``docs/api/compatibility.md``.
"""

from __future__ import annotations

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.errors import SetupError
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskLevel, ScanResult, Surface

__all__ = [
    "ConnectorSpec",
    "Evidence",
    "Finding",
    "Kind",
    "Risk",
    "RiskLevel",
    "ScanConfig",
    "ScanResult",
    "SetupError",
    "Surface",
    "scan",
]


def scan(config: ScanConfig) -> ScanResult:
    """Run an explicit scan, retaining incomplete results and setup failures.

    Check ``result.complete`` before using findings as evidence of absence.
    A setup error raises ``ValueError`` or the engine's documented setup error;
    it is never converted into an empty successful result.
    """
    if config.job_deadline_seconds is not None:
        raise SetupError(
            "job_deadline_seconds is a CLI process deadline; use the CLI or supervise "
            "the Python scan in a separate process"
        )
    return Engine(config).run()
