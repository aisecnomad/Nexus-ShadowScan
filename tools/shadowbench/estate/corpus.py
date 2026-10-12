"""Estate corpus model: labeled entities across the nine surfaces.

The corpus unit is an *entity*: one discoverable thing (an OAuth app, a bot,
a cloud agent, a client configuration in a home tree, a code repository's
integration, a network caller). Every entity is anchored to unique tokens
that appear inside its artifacts, so a tool's predictions can be attributed
to entities and counted as true positives, false positives, true negatives
and false negatives.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from tools.shadowbench.estate import taxonomy

SCHEMA = 1
CLASSES = ("positive", "control", "nearmiss")
DIFFICULTIES = ("easy", "medium", "hard")
MAX_CORPUS_BYTES = 8_000_000
#: Unit ids: `estate`, or `code:<name>` / `home:<name>` naming a directory
#: under the estate's `code/` or `home/`.
UNIT_KINDS = ("code", "home")
UNIT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*")
#: Secondary anchors are matched as substrings of tool output, like primary
#: ones; a short one would attribute unrelated predictions.
MIN_SECONDARY_ANCHOR = 6
FREEZE_SCHEMA = 1
_SHA256 = re.compile(r"[0-9a-f]{64}")


class CorpusError(ValueError):
    """Raised when the corpus file is malformed."""


class UnsafeEstateError(CorpusError):
    """Raised when the estate holds a symlink or a special file.

    The estate is untrusted input: a link could point a freeze, a validation
    or a tool run at files outside it, so it is rejected and never followed.
    """

    def __init__(self, entries: tuple[str, ...]) -> None:
        self.entries = entries
        shown = ", ".join(entries[:10])
        if len(entries) > 10:
            shown += f" and {len(entries) - 10} more"
        super().__init__(f"symlinks and special files are not allowed in the estate: {shown}")


@dataclass(frozen=True)
class Expected:
    fact: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Entity:
    id: str
    surface: str
    klass: str
    expected: tuple[Expected, ...]
    tolerated: tuple[str, ...]
    anchors: tuple[str, ...]
    artifacts: tuple[str, ...]
    unit: str
    registered: bool
    difficulty: str
    rationale: str

    @property
    def expected_facts(self) -> frozenset[str]:
        return frozenset(item.fact for item in self.expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "class": self.klass,
            "expected": [{"fact": e.fact, "evidence": list(e.evidence)} for e in self.expected],
            "tolerated": list(self.tolerated),
            "anchors": list(self.anchors),
            "artifacts": list(self.artifacts),
            "unit": self.unit,
            "registered": self.registered,
            "difficulty": self.difficulty,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ToleratedPrediction:
    """A (fact, anchor-substring) pair tolerated estate-wide.

    Predictions matching a tolerated pair are dropped before scoring: a tool
    may report them without penalty, but they are not required.
    """

    fact: str
    anchor: str

    def to_dict(self) -> dict[str, str]:
        return {"fact": self.fact, "anchor": self.anchor}


@dataclass(frozen=True)
class EstateCorpus:
    metadata: dict[str, Any]
    entities: tuple[Entity, ...]
    tolerated_global: tuple[ToleratedPrediction, ...] = ()
    schema: int = SCHEMA
    extra: dict[str, Any] = field(default_factory=dict)

    def by_class(self, klass: str) -> list[Entity]:
        return [entity for entity in self.entities if entity.klass == klass]

    def by_surface(self, surface: str) -> list[Entity]:
        return [entity for entity in self.entities if entity.surface == surface]

    def get(self, entity_id: str) -> Entity:
        for entity in self.entities:
            if entity.id == entity_id:
                return entity
        raise KeyError(entity_id)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": self.schema,
            "metadata": self.metadata,
            "entities": [entity.to_dict() for entity in self.entities],
        }
        if self.tolerated_global:
            payload["tolerated"] = [item.to_dict() for item in self.tolerated_global]
        payload.update(self.extra)
        return payload


def parse_unit(unit: str) -> tuple[str, str]:
    """Split a unit id into its kind and name: ("estate", "") or ("code"|"home", <name>)."""
    if unit == "estate":
        return "estate", ""
    kind, sep, name = unit.partition(":")
    if sep and kind in UNIT_KINDS and UNIT_NAME.fullmatch(name):
        return kind, name
    raise CorpusError(
        f"unit {unit!r} must be 'estate', 'code:<name>' or 'home:<name>' "
        f"with <name> matching {UNIT_NAME.pattern}"
    )


def unit_dir(unit: str) -> str | None:
    """The estate-relative directory a unit id names, or None for the whole estate."""
    kind, name = parse_unit(unit)
    return None if kind == "estate" else f"{kind}/{name}"


def _require_str(record: dict[str, Any], key: str, label: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise CorpusError(f"{label}: {key} must be a non-empty string")
    return value


def _str_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise CorpusError(f"{label} must be a list of non-empty strings")
    return tuple(value)


def entity_from_dict(record: dict[str, Any]) -> Entity:
    entity_id = _require_str(record, "id", "entity")
    label = f"entity {entity_id}"
    surface = _require_str(record, "surface", label)
    if surface not in taxonomy.SURFACES:
        raise CorpusError(f"{label}: unknown surface {surface}")
    klass = _require_str(record, "class", label)
    if klass not in CLASSES:
        raise CorpusError(f"{label}: unknown class {klass}")
    difficulty = _require_str(record, "difficulty", label)
    if difficulty not in DIFFICULTIES:
        raise CorpusError(f"{label}: unknown difficulty {difficulty}")

    expected_raw = record.get("expected", [])
    if not isinstance(expected_raw, list):
        raise CorpusError(f"{label}: expected must be a list")
    expected: list[Expected] = []
    seen_facts: set[str] = set()
    for item in expected_raw:
        if not isinstance(item, dict):
            raise CorpusError(f"{label}: expected entries must be objects")
        fact = _require_str(item, "fact", label)
        if not taxonomy.is_fact(fact):
            raise CorpusError(f"{label}: invalid fact {fact}")
        if fact in seen_facts:
            raise CorpusError(f"{label}: duplicate expected fact {fact}")
        seen_facts.add(fact)
        evidence = _str_tuple(item.get("evidence"), f"{label} evidence for {fact}")
        if not evidence:
            raise CorpusError(f"{label}: expected fact {fact} needs evidence")
        expected.append(Expected(fact=fact, evidence=evidence))

    tolerated = _str_tuple(record.get("tolerated"), f"{label} tolerated")
    for fact in tolerated:
        if not taxonomy.is_fact(fact):
            raise CorpusError(f"{label}: invalid tolerated fact {fact}")
        if fact in seen_facts:
            raise CorpusError(f"{label}: tolerated fact {fact} is also expected")

    if klass == "positive" and not expected:
        raise CorpusError(f"{label}: positives need at least one expected fact")
    if klass != "positive" and expected:
        raise CorpusError(f"{label}: {klass} entities must not carry expected facts")

    anchors = _str_tuple(record.get("anchors"), f"{label} anchors")
    if not anchors:
        raise CorpusError(f"{label}: at least one anchor is required")
    for anchor in anchors:
        if anchor != anchor.lower():
            raise CorpusError(f"{label}: anchors must be lowercase ({anchor})")
    if len(anchors[0]) < 4:
        raise CorpusError(f"{label}: the primary anchor must be at least 4 characters")
    for anchor in anchors[1:]:
        if len(anchor) < MIN_SECONDARY_ANCHOR:
            raise CorpusError(
                f"{label}: secondary anchors must be at least {MIN_SECONDARY_ANCHOR} characters ({anchor})"
            )

    artifacts = _str_tuple(record.get("artifacts"), f"{label} artifacts")
    if not artifacts:
        raise CorpusError(f"{label}: at least one artifact path is required")
    for artifact in artifacts:
        if artifact.startswith("/") or ".." in artifact.split("/"):
            raise CorpusError(f"{label}: artifact paths must be relative and inside the estate")

    registered = record.get("registered", False)
    if not isinstance(registered, bool):
        raise CorpusError(f"{label}: registered must be a boolean")
    if registered and klass != "positive":
        raise CorpusError(f"{label}: only positives can be registered")

    unit = record.get("unit", "estate")
    if not isinstance(unit, str) or not unit:
        raise CorpusError(f"{label}: unit must be a non-empty string")
    try:
        parse_unit(unit)
    except CorpusError as exc:
        raise CorpusError(f"{label}: {exc}") from None

    return Entity(
        id=entity_id,
        surface=surface,
        klass=klass,
        expected=tuple(expected),
        tolerated=tolerated,
        anchors=tuple(anchors),
        artifacts=artifacts,
        unit=unit,
        registered=registered,
        difficulty=difficulty,
        rationale=record.get("rationale", "") if isinstance(record.get("rationale", ""), str) else "",
    )


def corpus_from_dict(payload: dict[str, Any]) -> EstateCorpus:
    if payload.get("schema") != SCHEMA:
        raise CorpusError("unsupported corpus schema")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise CorpusError("corpus metadata must be an object")
    raw_entities = payload.get("entities")
    if not isinstance(raw_entities, list) or not raw_entities:
        raise CorpusError("corpus entities must be a non-empty list")
    entities = tuple(entity_from_dict(item) for item in raw_entities)

    ids = [entity.id for entity in entities]
    if len(set(ids)) != len(ids):
        raise CorpusError("entity ids must be unique")
    primaries = [entity.anchors[0] for entity in entities]
    if len(set(primaries)) != len(primaries):
        dupes = sorted({a for a in primaries if primaries.count(a) > 1})
        raise CorpusError(f"primary anchors must be unique estate-wide: {', '.join(dupes)}")

    tolerated_raw = payload.get("tolerated", [])
    if not isinstance(tolerated_raw, list):
        raise CorpusError("corpus tolerated must be a list")
    tolerated: list[ToleratedPrediction] = []
    for item in tolerated_raw:
        if not isinstance(item, dict):
            raise CorpusError("tolerated entries must be objects")
        fact = _require_str(item, "fact", "tolerated entry")
        if not taxonomy.is_fact(fact):
            raise CorpusError(f"tolerated entry: invalid fact {fact}")
        anchor = _require_str(item, "anchor", "tolerated entry").lower()
        tolerated.append(ToleratedPrediction(fact=fact, anchor=anchor))

    extra = {
        key: value
        for key, value in payload.items()
        if key not in {"schema", "metadata", "entities", "tolerated"}
    }
    return EstateCorpus(
        metadata=metadata,
        entities=entities,
        tolerated_global=tuple(tolerated),
        extra=extra,
    )


def load_corpus(path: Path) -> EstateCorpus:
    size = path.stat().st_size
    if size > MAX_CORPUS_BYTES:
        raise CorpusError(f"corpus file too large: {size} bytes")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CorpusError("corpus must be a JSON object")
    return corpus_from_dict(payload)


def save_corpus(corpus: EstateCorpus, path: Path) -> None:
    path.write_text(json.dumps(corpus.to_dict(), indent=1) + "\n", encoding="utf-8")


# --- estate files and the freeze manifest ---------------------------------------------------------


@dataclass(frozen=True)
class EstateTree:
    """An estate listing taken without following any symlink.

    Paths are POSIX and relative to the estate root, in `Path` order.
    `rejected` holds every entry that is neither a regular file nor a real
    directory (symlinks, FIFOs, sockets, devices); none of them is opened.
    """

    files: tuple[str, ...]
    dirs: tuple[str, ...]
    rejected: tuple[str, ...]


def _raise(exc: OSError) -> None:
    raise exc


def _path_order(rel: str) -> list[str]:
    return rel.split("/")


def walk_estate(estate: Path) -> EstateTree:
    """List the estate from `lstat` alone; an unreadable directory raises instead of vanishing."""
    try:
        mode = os.lstat(estate).st_mode
    except FileNotFoundError:
        raise CorpusError(f"estate {estate} does not exist") from None
    if not stat.S_ISDIR(mode):
        raise CorpusError(f"estate {estate} is not a directory (a symlinked root is not followed)")
    files: list[str] = []
    dirs: list[str] = []
    rejected: list[str] = []
    for current, dirnames, filenames in os.walk(estate, onerror=_raise, followlinks=False):
        base = Path(current).relative_to(estate)
        kept: list[str] = []
        for name in dirnames:
            rel = (base / name).as_posix()
            if stat.S_ISDIR(os.lstat(os.path.join(current, name)).st_mode):
                kept.append(name)
                dirs.append(rel)
            else:
                rejected.append(rel)
        dirnames[:] = kept
        for name in filenames:
            rel = (base / name).as_posix()
            if stat.S_ISREG(os.lstat(os.path.join(current, name)).st_mode):
                files.append(rel)
            else:
                rejected.append(rel)
    return EstateTree(
        files=tuple(sorted(files, key=_path_order)),
        dirs=tuple(sorted(dirs, key=_path_order)),
        rejected=tuple(sorted(rejected, key=_path_order)),
    )


def open_regular(path: Path) -> BinaryIO:
    """Open a regular file without following a symlink at its last component."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise UnsafeEstateError((str(path),)) from None
        raise
    handle = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
        handle.close()
        raise UnsafeEstateError((str(path),))
    return handle


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open_regular(path) as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def estate_prefix(estate: Path) -> str:
    """The key prefix FREEZE.json gives estate files: the estate directory's own name."""
    return Path(os.path.abspath(estate)).name


def estate_digests(estate: Path) -> dict[str, str]:
    """SHA-256 of every estate file, keyed `<estate dir name>/<relative path>`."""
    tree = walk_estate(estate)
    if tree.rejected:
        raise UnsafeEstateError(tree.rejected)
    prefix = estate_prefix(estate)
    return {f"{prefix}/{rel}": sha256_file(estate / rel) for rel in tree.files}


def freeze_digests(corpus_path: Path, estate: Path) -> dict[str, str]:
    """Every digest a freeze manifest records: the estate files plus the corpus file."""
    digests = estate_digests(estate)
    digests[corpus_path.name] = sha256_file(corpus_path)
    return digests


def freeze_drift(recorded: dict[str, str], current: dict[str, str]) -> list[str]:
    """Names added, removed or changed between two digest maps."""
    changed = {name for name in recorded.keys() & current.keys() if recorded[name] != current[name]}
    return sorted((recorded.keys() ^ current.keys()) | changed)


def load_freeze(path: Path) -> dict[str, str]:
    """The digest map of a freeze manifest; a malformed manifest raises."""
    with open_regular(path) as handle:
        raw = handle.read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise CorpusError(f"freeze manifest {path} is not valid JSON: {exc}") from None
    digests = payload.get("sha256") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != FREEZE_SCHEMA
        or not isinstance(digests, dict)
        or not digests
        or any(not isinstance(value, str) or not _SHA256.fullmatch(value) for value in digests.values())
    ):
        raise CorpusError(f"freeze manifest {path} is malformed")
    return {str(name): str(value) for name, value in digests.items()}
