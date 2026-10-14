"""Bounded lockfile inventory; locked packages never establish execution or agency.

No package manager, source URL, optional marker, or external file is evaluated.
Direct/transitive labels require explicit roots and unambiguous package edges.
"""

from __future__ import annotations

import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import yaml

from shadowscan.utils.safe_yaml import BoundedSafeLoader, YAMLResourceLimitError, strict_bounded_safe_load

LOCKFILE_NAMES = frozenset({"uv.lock", "poetry.lock", "pnpm-lock.yaml", "cargo.lock"})
# The scanner reads a lockfile up to its max_file_size, like any other manifest.
# These are the parser's own ceilings for any caller: the strict YAML loader's
# input bound (which also caps a pnpm document at its node limit) and counts
# well above what the supported ecosystems lock. pnpm's packages and snapshots
# are counted separately against the package limit.
MAX_LOCKFILE_BYTES = BoundedSafeLoader.MAX_INPUT_SIZE
MAX_PACKAGES = 65_536
MAX_EDGES = 262_144
MAX_STRUCTURE_NODES = 1_000_000


class LockfileError(ValueError):
    """A lockfile cannot be inventoried; the message is a fixed reason that never quotes it."""


@dataclass
class LockedPackage:
    ecosystem: str
    name: str
    version: str | None  # None when the lockfile records no version for the entry
    source: str = "unknown"
    relationship: str = "unknown"
    dependencies: list[tuple[str, str | None]] = field(default_factory=list)
    root: bool = False


@dataclass
class LockInventory:
    format: str
    packages: list[LockedPackage] = field(default_factory=list)
    edge_count: int = 0
    roots_known: bool = False
    limitations: list[str] = field(
        default_factory=lambda: [
            "Locked dependency inventory does not establish installation, execution, or agency.",
            "Optional dependencies and environment markers are not evaluated.",
            "Workspace links, peer variants, remote sources and ambiguous versions "
            "have unknown reachability.",
            "Source URLs and credentials are not retained.",
        ]
    )


def _bounded_structure(document: Any) -> None:
    stack = [(document, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_STRUCTURE_NODES or depth > 64:
            raise LockfileError("lockfile structure limit exceeded")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise LockfileError("lockfile object expected")
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise LockfileError("lockfile array expected")
    return value


def _name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[@A-Za-z0-9][@A-Za-z0-9_./+-]{0,255}", value):
        raise LockfileError("invalid lockfile package name")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}", value):
        raise LockfileError("invalid locked package version")
    return value


def _source(value: Any) -> str:
    if isinstance(value, dict):
        for kind in ("registry", "git", "url", "path", "directory", "editable", "virtual"):
            if kind in value:
                return "local" if kind in {"path", "directory", "editable", "virtual"} else kind
        source_kind = value.get("type")
        return str(source_kind) if source_kind in {"git", "url", "directory", "file", "legacy"} else "unknown"
    if isinstance(value, str):
        return (
            "registry" if value.startswith("registry+") else "git" if value.startswith("git+") else "unknown"
        )
    return "unknown"


def _toml_inventory(name: str, data: dict[str, Any]) -> LockInventory:
    result = LockInventory(name)
    packages = _list(data.get("package", []))
    if len(packages) > MAX_PACKAGES:
        raise LockfileError("lockfile package limit exceeded")
    if name == "uv.lock" and (type(data.get("version")) is not int or data.get("version") != 1):
        raise LockfileError("unsupported uv lockfile version")
    if name == "cargo.lock" and (type(data.get("version")) is not int or data.get("version") not in {3, 4}):
        raise LockfileError("unsupported Cargo lockfile version")
    if name == "poetry.lock":
        version = _mapping(data.get("metadata", {})).get("lock-version")
        if version not in {"1.1", "2.0", "2.1"}:
            raise LockfileError("unsupported Poetry lockfile version")
    for entry in packages:
        item = _mapping(entry)
        source = item.get("source")
        recorded = item.get("version")
        package = LockedPackage(
            "cargo" if name == "cargo.lock" else "pypi",
            _name(item.get("name")),
            # uv records no version for a virtual root or a dynamic-version member.
            None if name == "uv.lock" and recorded is None else _version(recorded),
            _source(source),
        )
        if name == "uv.lock":
            package.root = isinstance(source, dict) and any(
                source.get(k) == "." for k in ("virtual", "editable")
            )
            for dependency in _list(item.get("dependencies", [])):
                dep = _mapping(dependency)
                package.dependencies.append(
                    (_name(dep.get("name")), _version(dep["version"]) if "version" in dep else None)
                )
        elif name == "cargo.lock":
            for dependency in _list(item.get("dependencies", [])):
                if not isinstance(dependency, str):
                    raise LockfileError("invalid Cargo dependency")
                parts = dependency.split(" ", 2)
                package.dependencies.append((_name(parts[0]), _version(parts[1]) if len(parts) > 1 else None))
        else:
            for dependency in _mapping(item.get("dependencies", {})):
                # Poetry dependency values are constraints, not locked versions.
                package.dependencies.append((_name(dependency), None))
        result.edge_count += len(package.dependencies)
        if result.edge_count > MAX_EDGES:
            raise LockfileError("lockfile edge limit exceeded")
        result.packages.append(package)
    result.roots_known = any(p.root for p in result.packages)
    return result


def _pnpm_remote(reference: str) -> bool:
    """A git or tarball reference: a remote source the inventory never resolves or retains."""
    return "://" in reference or reference.startswith(("git+", "http:", "https:"))


def _pnpm_identity(key: str) -> str:
    """A packages/snapshots key without its leading slash (v6) or peer suffix (v9)."""
    return key.lstrip("/").split("(", 1)[0]


def _pnpm_key(key: str) -> tuple[str | None, str | None]:
    """Return the name and version a packages/snapshots key proves, None for each it does not.

    v6 ``/name@version`` and v9 ``name@version`` prove both, ``@scope/name``
    included. A git or tarball key proves at most the name: v9 ``name@<url>``
    does; v6 ``github.com/org/repo/<commit>`` or ``@host/path.tgz`` does not,
    so the entry's own ``name`` and ``version`` fields are consulted.
    """
    key = _pnpm_identity(key)
    scoped = key.startswith("@")
    name, separator, version = (key[1:] if scoped else key).partition("@")
    if scoped:
        name = "@" + name
    if separator and ("/" in version or _pnpm_remote(version)):
        return _name(name), None
    if separator:
        return _name(name), _version(version)
    if "/" in key:
        return None, None
    raise LockfileError("unsupported pnpm package key")


def _pnpm_source(item: dict[str, Any]) -> str:
    """The source kind a git or tarball entry's resolution records; the URL itself is dropped."""
    resolution = item.get("resolution")
    if not isinstance(resolution, dict):
        return "unknown"
    if resolution.get("type") == "git":
        return "git"
    return "url" if "tarball" in resolution else "unknown"


def _pnpm_reference(name: str, reference: str) -> tuple[str, str] | None:
    # Peer snapshots are distinct installations. This compact package inventory
    # does not model them, so never merge their edges into reachability claims.
    if "(" in reference:
        return None
    # Links and remote sources resolve no registry package: reachability stays unknown.
    if reference.startswith(("link:", "file:", "workspace:")) or _pnpm_remote(reference):
        return None
    if reference.startswith("npm:"):
        reference = reference[4:]
    if "@" in reference or reference.startswith("/"):
        resolved_name, version = _pnpm_key(reference)
        return None if resolved_name is None or version is None else (resolved_name, version)
    if "/" in reference:
        # v6 git reference ``github.com/org/repo/<commit>``.
        return None
    return _name(name), _version(reference)


def _pnpm_inventory(data: dict[str, Any]) -> LockInventory:
    version = str(data.get("lockfileVersion"))
    if version not in {"6", "6.0", "9", "9.0"}:
        raise LockfileError("unsupported pnpm lockfile version (supported: 6 and 9)")
    result = LockInventory("pnpm-lock.yaml")
    entries = _mapping(data.get("packages", {}))
    snapshots = _mapping(data.get("snapshots", {}))
    if max(len(entries), len(snapshots)) > MAX_PACKAGES:
        raise LockfileError("lockfile package limit exceeded")
    grouped_snapshots: dict[str, list[dict[str, Any]]] = {}
    for key, value in snapshots.items():
        _pnpm_key(key)  # a malformed key rejects the lockfile
        record = _mapping(value)
        if "(" not in key:
            grouped_snapshots.setdefault(_pnpm_identity(key), []).append(record)
    for key, entry in entries.items():
        package_name, package_version = _pnpm_key(key)
        item = _mapping(entry)
        if package_name is not None and package_version is not None:
            package = LockedPackage("npm", package_name, package_version, "registry")
        else:
            # A git or tarball entry: v6 records its name, and both record the
            # version it resolved to when one is known.
            recorded = item.get("version")
            package = LockedPackage(
                "npm",
                _name(item.get("name")) if package_name is None else package_name,
                None if recorded is None else _version(recorded),
                _pnpm_source(item),
            )
        # v9 snapshots contain resolved edges; peer variants can share one inventory identity.
        edge_records = [item] if version.startswith("6") else grouped_snapshots.get(_pnpm_identity(key), [])
        for record in edge_records:
            for section in ("dependencies", "optionalDependencies"):
                for dep_name, reference in _mapping(record.get(section, {})).items():
                    if not isinstance(reference, str):
                        raise LockfileError("invalid pnpm dependency reference")
                    resolved = _pnpm_reference(dep_name, reference)
                    if resolved is not None:
                        package.dependencies.append(resolved)
        result.edge_count += len(package.dependencies)
        if result.edge_count > MAX_EDGES:
            raise LockfileError("lockfile edge limit exceeded")
        result.packages.append(package)
    importers = _mapping(data.get("importers", {}))
    # v6 permits a single root importer at the document level.
    if not importers and any(section in data for section in ("dependencies", "devDependencies")):
        importers = {".": data}
    roots: list[tuple[str, str | None]] = []
    for importer in importers.values():
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for dep_name, spec in _mapping(_mapping(importer).get(section, {})).items():
                reference = _mapping(spec).get("version")
                if not isinstance(reference, str):
                    raise LockfileError("invalid pnpm importer version")
                resolved = _pnpm_reference(dep_name, reference)
                if resolved is not None:
                    roots.append(resolved)
    result.edge_count += len(roots)
    if result.edge_count > MAX_EDGES:
        raise LockfileError("lockfile edge limit exceeded")
    if importers:
        result.packages.append(LockedPackage("npm", "workspace", "0", "local", dependencies=roots, root=True))
        result.roots_known = True
    return result


def _relationships(result: LockInventory) -> None:
    by_name: dict[str, list[int]] = {}
    by_id: dict[tuple[str, str], list[int]] = {}
    for number, package in enumerate(result.packages):
        by_name.setdefault(package.name, []).append(number)
        if package.version is not None:
            by_id.setdefault((package.name, package.version), []).append(number)
    visited = {i for i, p in enumerate(result.packages) if p.root}
    pending = deque((i, 0) for i in sorted(visited))
    while pending:
        index, depth = pending.popleft()
        for name, version in result.packages[index].dependencies:
            matches = by_name.get(name, []) if version is None else by_id.get((name, version), [])
            if len(matches) != 1:
                continue
            target = matches[0]
            if target in visited:
                continue
            visited.add(target)
            result.packages[target].relationship = "direct" if depth == 0 else "transitive"
            pending.append((target, depth + 1))


def parse_lockfile(name: str, text: str) -> LockInventory:
    """Parse a supported bounded lockfile; a ``LockfileError`` names why one is rejected."""
    name = name.lower()
    if name not in LOCKFILE_NAMES:
        raise LockfileError("unsupported lockfile")
    if len(text.encode("utf-8")) > MAX_LOCKFILE_BYTES:
        raise LockfileError("lockfile byte limit exceeded")
    try:
        data = strict_bounded_safe_load(text) if name == "pnpm-lock.yaml" else tomllib.loads(text)
    except YAMLResourceLimitError:
        raise LockfileError("YAML safety limit exceeded") from None
    except (ValueError, RecursionError, yaml.YAMLError):
        # A parser message can quote the input; the reason stays fixed.
        raise LockfileError("invalid YAML" if name == "pnpm-lock.yaml" else "invalid TOML") from None
    data = _mapping(data)
    _bounded_structure(data)
    result = _pnpm_inventory(data) if name == "pnpm-lock.yaml" else _toml_inventory(name, data)
    _relationships(result)
    return result
