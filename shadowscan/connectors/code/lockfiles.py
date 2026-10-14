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

from shadowscan.utils.safe_yaml import strict_bounded_safe_load

LOCKFILE_NAMES = frozenset({"uv.lock", "poetry.lock", "pnpm-lock.yaml", "cargo.lock"})
MAX_LOCKFILE_BYTES = 1_000_000
MAX_PACKAGES = 4096
MAX_EDGES = 16384
MAX_STRUCTURE_NODES = 50000


@dataclass
class LockedPackage:
    ecosystem: str
    name: str
    version: str
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
            raise ValueError("lockfile structure limit exceeded")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ValueError("lockfile object expected")
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError("lockfile array expected")
    return value


def _name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[@A-Za-z0-9][@A-Za-z0-9_./+-]{0,255}", value):
        raise ValueError("invalid lockfile package name")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}", value):
        raise ValueError("invalid locked package version")
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
        raise ValueError("lockfile package limit exceeded")
    if name == "uv.lock" and (type(data.get("version")) is not int or data.get("version") != 1):
        raise ValueError("unsupported uv lockfile version")
    if name == "cargo.lock" and (type(data.get("version")) is not int or data.get("version") not in {3, 4}):
        raise ValueError("unsupported Cargo lockfile version")
    if name == "poetry.lock":
        version = _mapping(data.get("metadata", {})).get("lock-version")
        if version not in {"1.1", "2.0", "2.1"}:
            raise ValueError("unsupported Poetry lockfile version")
    for entry in packages:
        item = _mapping(entry)
        source = item.get("source")
        package = LockedPackage(
            "cargo" if name == "cargo.lock" else "pypi",
            _name(item.get("name")),
            _version(item.get("version")),
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
                    raise ValueError("invalid Cargo dependency")
                parts = dependency.split(" ", 2)
                package.dependencies.append((_name(parts[0]), _version(parts[1]) if len(parts) > 1 else None))
        else:
            for dependency in _mapping(item.get("dependencies", {})):
                # Poetry dependency values are constraints, not locked versions.
                package.dependencies.append((_name(dependency), None))
        result.edge_count += len(package.dependencies)
        if result.edge_count > MAX_EDGES:
            raise ValueError("lockfile edge limit exceeded")
        result.packages.append(package)
    result.roots_known = any(p.root for p in result.packages)
    return result


def _pnpm_key(key: str) -> tuple[str, str]:
    key = key.lstrip("/").split("(", 1)[0]
    # v6 /name@version and v9 name@version, including @scope/name.
    name, separator, version = key.rpartition("@")
    if not separator or not name:
        raise ValueError("unsupported pnpm package key")
    return _name(name), _version(version)


def _pnpm_reference(name: str, reference: str) -> tuple[str, str] | None:
    # Peer snapshots are distinct installations. This compact package inventory
    # does not model them, so never merge their edges into reachability claims.
    if "(" in reference:
        return None
    if reference.startswith(("link:", "file:", "workspace:", "http:", "https:")):
        return None
    if reference.startswith("npm:"):
        reference = reference[4:]
    if "@" in reference or reference.startswith("/"):
        return _pnpm_key(reference)
    return _name(name), _version(reference)


def _pnpm_inventory(data: dict[str, Any]) -> LockInventory:
    version = str(data.get("lockfileVersion"))
    if version not in {"6", "6.0", "9", "9.0"}:
        raise ValueError("unsupported pnpm lockfile version (supported: 6 and 9)")
    result = LockInventory("pnpm-lock.yaml")
    entries = _mapping(data.get("packages", {}))
    snapshots = _mapping(data.get("snapshots", {}))
    if len(entries) + len(snapshots) > MAX_PACKAGES:
        raise ValueError("lockfile package limit exceeded")
    grouped_snapshots: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for key, value in snapshots.items():
        identity = _pnpm_key(key)
        record = _mapping(value)
        if "(" not in key:
            grouped_snapshots.setdefault(identity, []).append(record)
    for key, entry in entries.items():
        package_name, package_version = _pnpm_key(key)
        item = _mapping(entry)
        package = LockedPackage("npm", package_name, package_version, "registry")
        # v9 snapshots contain resolved edges; peer variants can share one inventory identity.
        edge_records = (
            [item] if version.startswith("6") else grouped_snapshots.get((package_name, package_version), [])
        )
        for record in edge_records:
            for section in ("dependencies", "optionalDependencies"):
                for dep_name, reference in _mapping(record.get(section, {})).items():
                    if not isinstance(reference, str):
                        raise ValueError("invalid pnpm dependency reference")
                    resolved = _pnpm_reference(dep_name, reference)
                    if resolved is not None:
                        package.dependencies.append(resolved)
        result.edge_count += len(package.dependencies)
        if result.edge_count > MAX_EDGES:
            raise ValueError("lockfile edge limit exceeded")
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
                    raise ValueError("invalid pnpm importer version")
                resolved = _pnpm_reference(dep_name, reference)
                if resolved is not None:
                    roots.append(resolved)
    result.edge_count += len(roots)
    if result.edge_count > MAX_EDGES:
        raise ValueError("lockfile edge limit exceeded")
    if importers:
        result.packages.append(LockedPackage("npm", "workspace", "0", "local", dependencies=roots, root=True))
        result.roots_known = True
    return result


def _relationships(result: LockInventory) -> None:
    by_name: dict[str, list[int]] = {}
    by_id: dict[tuple[str, str], list[int]] = {}
    for number, package in enumerate(result.packages):
        by_name.setdefault(package.name, []).append(number)
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
    """Parse a supported bounded lockfile, rejecting malformed/unsupported inputs."""
    name = name.lower()
    if name not in LOCKFILE_NAMES:
        raise ValueError("unsupported lockfile")
    if len(text.encode("utf-8")) > MAX_LOCKFILE_BYTES:
        raise ValueError("lockfile byte limit exceeded")
    data = strict_bounded_safe_load(text) if name == "pnpm-lock.yaml" else tomllib.loads(text)
    data = _mapping(data)
    _bounded_structure(data)
    result = _pnpm_inventory(data) if name == "pnpm-lock.yaml" else _toml_inventory(name, data)
    _relationships(result)
    return result
