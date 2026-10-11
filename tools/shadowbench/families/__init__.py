"""Case families for the six export-style surfaces plus the endpoint, network and runtime wrappers.

Each family returns a :class:`Draft`: the platform-native records it adds to a
case together with the expected entities (label and evidence) and tolerated
keys. Surface modules assemble drafts into one export per case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.benchmark.common import Rand
from tools.shadowbench.contract import TruthEntity


@dataclass
class Draft:
    family: str
    label: str
    difficulty: str
    rationale: str
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Native records keyed by collection (``apps``, ``servicePrincipals``, ``flows`` ...)."""
    files: dict[str, str] = field(default_factory=dict)
    expected: list[TruthEntity] = field(default_factory=list)
    tolerated: list[str] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)


def iso(rd: Rand, year: int = 2026, month_lo: int = 1, month_hi: int = 9) -> str:
    month, day = rd.randint(month_lo, month_hi), rd.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}T{rd.randint(0, 23):02d}:{rd.randint(0, 59):02d}:00Z"


def person(rd: Rand) -> str:
    return str(
        rd.choice(("alice", "bilal", "chen", "dana", "eitan", "fatima", "gopal", "hana", "ivan", "jules"))
    )


def email(rd: Rand) -> str:
    return f"{person(rd)}@acme.example"


def guid(rd: Rand) -> str:
    h = rd.hexid(32)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
