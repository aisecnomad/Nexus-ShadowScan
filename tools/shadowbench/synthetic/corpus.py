"""Corpus model for ShadowBench: cases, ground truth, loading and digests.

A case is one input a tool is pointed at (an export, a home directory, a log
window, a process table, a set of services). Its ground truth is a list of
expected entities, each with a label and the evidence that justifies it, plus
tolerated keys a tool may report without penalty. Everything else a tool
reports on that case is a false positive.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from tools.shadowbench.synthetic.contract import LABELS, MODALITIES, SURFACES, TruthEntity

LABEL_RANK = {"none": 0, "llm": 1, "agent": 2}


@dataclass
class Case:
    case_id: str
    surface: str
    modality: str
    family: str
    difficulty: str
    rationale: str
    files: dict[str, str] = field(default_factory=dict)
    """Text files written under ``inputs/`` (POSIX relative paths)."""
    processes: list[dict[str, Any]] = field(default_factory=list)
    """``runtime/live``: processes to spawn (``name``, ``argv``, ``username``)."""
    services: list[dict[str, Any]] = field(default_factory=list)
    """``network/active``: services to serve (``port``, ``product``, ``routes``)."""
    expected: list[TruthEntity] = field(default_factory=list)
    tolerated: list[str] = field(default_factory=list)
    """Entity keys a tool may report without penalty (supporting files, related identities)."""
    decoys: list[str] = field(default_factory=list)
    """Entity keys of records labeled ``none``: the true negatives a tool must leave alone."""
    checkout: dict[str, Any] | None = None
    """``code/checkout``: the pinned repository (id, host, path, commit) copied to ``inputs/repo``."""

    @property
    def label(self) -> str:
        """The case-level label: the strongest expected label, ``none`` when nothing is expected."""
        best = "none"
        for e in self.expected:
            if LABEL_RANK[e.label] > LABEL_RANK[best]:
                best = e.label
        return best

    @property
    def positive(self) -> bool:
        return self.label != "none"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.case_id,
            "surface": self.surface,
            "modality": self.modality,
            "family": self.family,
            "label": self.label,
            "difficulty": self.difficulty,
            "rationale": self.rationale,
        }
        if self.files:
            out["files"] = dict(sorted(self.files.items()))
        if self.processes:
            out["processes"] = self.processes
        if self.services:
            out["services"] = self.services
        if self.checkout:
            out["checkout"] = self.checkout
        out["truth"] = {
            "expected": [e.to_json() for e in self.expected],
            "tolerated": sorted(self.tolerated),
            "decoys": sorted(self.decoys),
        }
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Case:
        truth = data.get("truth") or {}
        expected = [
            TruthEntity(
                kind=str(e["kind"]),
                key=str(e["key"]),
                label=str(e["label"]),
                attributes=dict(e.get("attributes") or {}),
                evidence=str(e.get("evidence", "")),
            )
            for e in truth.get("expected", [])
        ]
        case = cls(
            case_id=str(data["id"]),
            surface=str(data["surface"]),
            modality=str(data["modality"]),
            family=str(data["family"]),
            difficulty=str(data["difficulty"]),
            rationale=str(data["rationale"]),
            files={str(k): str(v) for k, v in (data.get("files") or {}).items()},
            processes=list(data.get("processes") or []),
            services=list(data.get("services") or []),
            expected=expected,
            tolerated=[str(k) for k in truth.get("tolerated", [])],
            decoys=[str(k) for k in truth.get("decoys", [])],
            checkout=dict(data["checkout"]) if isinstance(data.get("checkout"), dict) else None,
        )
        validate_case(case)
        if "label" in data and data["label"] != case.label:
            raise ValueError(f"{case.case_id}: stored label {data['label']!r} disagrees with truth")
        return case


def validate_case(case: Case) -> None:
    if case.surface not in SURFACES:
        raise ValueError(f"{case.case_id}: unknown surface {case.surface!r}")
    if case.modality not in MODALITIES[case.surface]:
        raise ValueError(f"{case.case_id}: unknown modality {case.modality!r} for {case.surface}")
    seen: set[str] = set()
    for path in case.files:
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not path or path.startswith("./"):
            raise ValueError(f"{case.case_id}: unsafe path {path!r}")
        folded = path.casefold()
        if folded in seen:
            raise ValueError(f"{case.case_id}: path {path!r} collides under case folding")
        seen.add(folded)
    keys = [e.key for e in case.expected]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{case.case_id}: duplicate expected keys")
    for e in case.expected:
        if e.label not in LABELS or e.label == "none":
            raise ValueError(f"{case.case_id}: expected entity {e.key} has label {e.label!r}")
        if not e.evidence:
            raise ValueError(f"{case.case_id}: expected entity {e.key} has no evidence")
    if set(case.tolerated) & set(keys):
        raise ValueError(f"{case.case_id}: a key is both expected and tolerated")
    if set(case.decoys) & (set(keys) | set(case.tolerated)):
        raise ValueError(f"{case.case_id}: a decoy key is also expected or tolerated")


@dataclass
class Corpus:
    cases: list[Case]
    seed: int
    generator_digest: str
    created: str
    notes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "benchmark": "shadowbench",
            "version": 1,
            "seed": self.seed,
            "generator_digest": self.generator_digest,
            "created": self.created,
            "notes": self.notes,
            "cases": [c.to_json() for c in self.cases],
        }

    def by_surface(self) -> dict[str, list[Case]]:
        out: dict[str, list[Case]] = {s: [] for s in SURFACES}
        for c in self.cases:
            out[c.surface].append(c)
        return out


def dump_corpus(corpus: Corpus, path: Path) -> str:
    text = json.dumps(corpus.to_json(), indent=1, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_text(text)


def load_corpus(path: Path) -> Corpus:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("benchmark") != "shadowbench":
        raise ValueError(f"{path}: not a ShadowBench corpus")
    cases = [Case.from_json(c) for c in data["cases"]]
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate case ids")
    return Corpus(
        cases=cases,
        seed=int(data["seed"]),
        generator_digest=str(data["generator_digest"]),
        created=str(data["created"]),
        notes=dict(data.get("notes") or {}),
    )


def corpus_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_files(paths: Iterable[Path], root: Path) -> str:
    """SHA-256 over file names and bytes, so a corpus names the code that made it."""
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()
