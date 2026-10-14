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
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, TypeGuard

from tools.shadowbench.cases.contract import LABELS, MODALITIES, SURFACES, TruthEntity

LABEL_RANK = {"none": 0, "llm": 1, "agent": 2}
LEGACY_STREAMS = "legacy"
STREAM_SCHEMES: tuple[str, ...] = ("sha256", LEGACY_STREAMS)
"""How the generator seeds each modality's random stream (``generate.stream_seed``)."""
LOOPBACK = "127.0.0.1"
CHECKOUT_ID = re.compile(r"[A-Za-z0-9._-]+")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


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
            files={str(k): str(v) for k, v in _typed(data, "files", dict).items()},
            processes=list(_typed(data, "processes", list)),
            services=list(_typed(data, "services", list)),
            expected=expected,
            tolerated=[str(k) for k in truth.get("tolerated", [])],
            decoys=[str(k) for k in truth.get("decoys", [])],
            checkout=dict(_typed(data, "checkout", dict)) if data.get("checkout") is not None else None,
        )
        validate_case(case)
        if "label" in data and data["label"] != case.label:
            raise ValueError(f"{case.case_id}: stored label {data['label']!r} disagrees with truth")
        return case


def _typed(data: dict[str, Any], name: str, kind: type[dict[str, Any]] | type[list[Any]]) -> Any:
    """A case field of the expected JSON type (empty when absent); anything else is malformed."""
    value = data.get(name)
    if value is None:
        return kind()
    if not isinstance(value, kind):
        raise ValueError(f"{data.get('id')}: {name} must be a JSON {'object' if kind is dict else 'array'}")
    return value


def _is_port(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _validate_inputs(case: Case) -> None:
    """The case's inputs are well formed and only ever land under the case's ``inputs/`` directory.

    The runner writes ``files`` under ``inputs/``, copies the checkout from ``<checkouts>/<id>``,
    binds each service and spawns each process, so a malformed value here could write or read
    outside the case, or silently stage nothing and let an empty input score as a clean negative.
    """
    cid = case.case_id
    shape = (case.surface, case.modality)
    if (case.checkout is not None) != (case.surface == "code"):
        raise ValueError(f"{cid}: code cases, and only code cases, carry a checkout")
    if case.checkout is not None and case.files:
        raise ValueError(f"{cid}: a case has either a checkout or files, not both")
    if bool(case.services) != (shape == ("network", "active")):
        raise ValueError(f"{cid}: network/active cases, and only those, carry services")
    if bool(case.processes) != (shape == ("runtime", "live")):
        raise ValueError(f"{cid}: runtime/live cases, and only those, carry processes")
    seen: set[str] = set()
    for path in case.files:
        pure = PurePosixPath(path)
        # Only the canonical spelling is accepted: "a//b", "a/./b", "./a" and "a/" name a file
        # another key may also name, and a backslash or NUL is not part of a portable POSIX path.
        if (
            not pure.parts
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
            or "\\" in path
            or "\0" in path
        ):
            raise ValueError(f"{cid}: unsafe path {path!r}")
        folded = path.casefold()
        if folded in seen:
            raise ValueError(f"{cid}: path {path!r} collides under case folding")
        seen.add(folded)
    if case.checkout is not None:
        co = case.checkout
        rid = co.get("id")
        if not isinstance(rid, str) or not CHECKOUT_ID.fullmatch(rid) or rid in (".", ".."):
            raise ValueError(f"{cid}: unsafe checkout id {rid!r}")
        if not isinstance(co.get("commit"), str) or not COMMIT.fullmatch(co["commit"]):
            raise ValueError(f"{cid}: checkout commit {co.get('commit')!r} is not a full object id")
        for part in ("host", "path"):
            if not isinstance(co.get(part), str) or not co[part]:
                raise ValueError(f"{cid}: checkout {part} must be a non-empty string")
    ports: set[int] = set()
    for svc in case.services:
        if not isinstance(svc, dict):
            raise ValueError(f"{cid}: a service must be an object")
        if svc.get("ip") != LOOPBACK:
            raise ValueError(f"{cid}: service ip {svc.get('ip')!r} is not {LOOPBACK}")
        port = svc.get("port")
        if not _is_port(port):
            raise ValueError(f"{cid}: service port {port!r} is not an integer in 1..65535")
        if port in ports:
            raise ValueError(f"{cid}: two services on port {port}")
        ports.add(port)
        if not isinstance(svc.get("product"), str) or not svc["product"]:
            raise ValueError(f"{cid}: service on port {port} has no product")
    indexes: set[int] = set()
    for proc in case.processes:
        if not isinstance(proc, dict):
            raise ValueError(f"{cid}: a process must be an object")
        index, name, argv = proc.get("index"), proc.get("name"), proc.get("argv")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index in indexes:
            raise ValueError(f"{cid}: process index {index!r} is not a unique non-negative integer")
        indexes.add(index)
        if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\0" in name:
            raise ValueError(f"{cid}: process {index} has an unsafe name {name!r}")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(a, str) and "\0" not in a for a in argv)
        ):
            raise ValueError(f"{cid}: process {index} argv must be a non-empty list of strings")
        if not isinstance(proc.get("username"), str) or not proc["username"]:
            raise ValueError(f"{cid}: process {index} has no username")


def validate_case(case: Case) -> None:
    if case.surface not in SURFACES:
        raise ValueError(f"{case.case_id}: unknown surface {case.surface!r}")
    if case.modality not in MODALITIES[case.surface]:
        raise ValueError(f"{case.case_id}: unknown modality {case.modality!r} for {case.surface}")
    _validate_inputs(case)
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
    per_surface: int | None = None
    """The ``--per-surface`` the cases were generated with; ``None`` in corpora written before it was kept."""
    stream_scheme: str | None = None
    """One of ``STREAM_SCHEMES``; ``None`` in corpora written before it was kept, which are ``legacy``."""

    @property
    def streams(self) -> str:
        """The stream scheme the cases were built with: the recorded one, else ``legacy``."""
        return self.stream_scheme or LEGACY_STREAMS

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"benchmark": "shadowbench", "version": 1, "seed": self.seed}
        if self.per_surface is not None:
            out["per_surface"] = self.per_surface
        if self.stream_scheme is not None:
            out["stream_scheme"] = self.stream_scheme
        out.update(
            generator_digest=self.generator_digest,
            created=self.created,
            notes=self.notes,
            cases=[c.to_json() for c in self.cases],
        )
        return out

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
    per_surface = data.get("per_surface")
    if per_surface is not None and (
        not isinstance(per_surface, int) or isinstance(per_surface, bool) or per_surface < 0
    ):
        raise ValueError(f"{path}: per_surface {per_surface!r} is not a non-negative integer")
    # Absent means the legacy scheme; anything present must name a scheme, or verify would rebuild
    # the cases with streams other than the ones they were drawn from.
    stream_scheme = data.get("stream_scheme")
    if stream_scheme is not None and stream_scheme not in STREAM_SCHEMES:
        raise ValueError(f"{path}: stream_scheme {stream_scheme!r} is not one of {', '.join(STREAM_SCHEMES)}")
    return Corpus(
        cases=cases,
        seed=int(data["seed"]),
        generator_digest=str(data["generator_digest"]),
        created=str(data["created"]),
        notes=dict(data.get("notes") or {}),
        per_surface=per_surface,
        stream_scheme=stream_scheme,
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
