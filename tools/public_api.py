"""Snapshot the public Python API of ``shadowscan`` as deterministic JSON.

The public modules are ``shadowscan``, the connector registry
``shadowscan.connectors`` (the plugin API) and every module the API reference
renders (a ``::: module`` line in ``docs/api/*.md``). A module's public names
are its ``__all__``. This module records each name's kind and, for a function
or class, its signature, bases and own public members, in
``docs/reference/python-api.json``; a test fails when the committed snapshot
differs from the code::

    python -m tools.public_api          # rewrite the snapshot (make python-api)
    python -m tools.public_api --check  # exit 1 when it is stale

Values are not recorded: a constant's type is part of the contract, its value
(a limit, a weight) is not. Signatures are rendered from the source
annotations with defaults reduced to stable text, so the snapshot is the same
on every supported Python. ``docs/reference/stability.md`` states the policy.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import importlib
import inspect
import json
import logging
import re
import sys
import types
import typing
from pathlib import Path
from typing import Any

from tools.snapshot_json import drift, drift_report, dumps

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "reference" / "python-api.json"
API_DOCS = ROOT / "docs" / "api"
SCHEMA = "shadowscan.python-api/v1"
# Public without an API reference page: the package (``__version__``) and the
# registry third-party connectors are loaded through.
EXTRA_MODULES = ("shadowscan", "shadowscan.connectors")
_DIRECTIVE = re.compile(r"^::: ([\w.]+)\s*$", re.MULTILINE)
_BUILTIN_TYPES = (bool, int, float, complex, str, bytes, tuple, list, dict, set, frozenset, type(None))


def public_modules() -> list[str]:
    """Every module the API reference renders, plus :data:`EXTRA_MODULES`, sorted."""
    names = set(EXTRA_MODULES)
    for page in sorted(API_DOCS.glob("*.md")):
        names.update(_DIRECTIVE.findall(page.read_text(encoding="utf-8")))
    return sorted(names)


def defined_public_names(module: types.ModuleType) -> list[str]:
    """Non-underscore names the module's own top level binds, minus loggers and modules.

    The candidates for ``__all__``: what a module defines, not what it imports.
    """
    source = inspect.getsource(module)
    names: list[str] = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            names += [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return [
        name
        for name in dict.fromkeys(names)
        if not name.startswith("_")
        and hasattr(module, name)
        and not isinstance(getattr(module, name), logging.Logger | types.ModuleType)
    ]


def _annotation(value: Any) -> str:
    if value is inspect.Parameter.empty:
        return ""
    if isinstance(value, str):
        return value
    return inspect.formatannotation(value)


def _stable(value: Any) -> str:
    """A default value as text that does not depend on hash seeds, addresses or the Python version."""
    if value is None or isinstance(value, bool | int | float | str | bytes):
        return repr(value)
    if value is getattr(dataclasses, "_HAS_DEFAULT_FACTORY", None):
        return "<factory>"  # a dataclass field's default_factory, as dataclasses itself shows it
    if isinstance(value, enum.Enum):
        return f"{type(value).__qualname__}.{value.name}"
    if isinstance(value, tuple):
        items = ", ".join(_stable(item) for item in value)
        return f"({items},)" if len(value) == 1 else f"({items})"
    if isinstance(value, list):
        return "[" + ", ".join(_stable(item) for item in value) + "]"
    if isinstance(value, frozenset | set):
        items = ", ".join(sorted(_stable(item) for item in value))
        return f"{type(value).__name__}({{{items}}})" if value else f"{type(value).__name__}()"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_stable(k)}: {_stable(v)}" for k, v in sorted(value.items(), key=str)) + "}"
    if isinstance(value, type) or callable(value):
        return getattr(value, "__qualname__", type(value).__qualname__)
    return f"<{type(value).__qualname__}>"


def _signature(obj: Any) -> str | None:
    """``(a: int, /, b: str = 'x', *, c: bool = False) -> None`` from source annotations, or None."""
    try:
        signature = inspect.signature(obj)
    except (TypeError, ValueError):
        return None
    parts: list[str] = []
    kinds = inspect.Parameter
    previous = None
    for parameter in signature.parameters.values():
        kind = parameter.kind
        if previous is kinds.POSITIONAL_ONLY and kind is not kinds.POSITIONAL_ONLY:
            parts.append("/")
        if kind is kinds.KEYWORD_ONLY and previous not in (kinds.KEYWORD_ONLY, kinds.VAR_POSITIONAL):
            parts.append("*")
        stars = "*" if kind is kinds.VAR_POSITIONAL else "**" if kind is kinds.VAR_KEYWORD else ""
        text = stars + parameter.name
        annotation = _annotation(parameter.annotation)
        if annotation:
            text += f": {annotation}"
        if parameter.default is not kinds.empty:
            text += f" = {_stable(parameter.default)}" if annotation else f"={_stable(parameter.default)}"
        parts.append(text)
        previous = kind
    if previous is kinds.POSITIONAL_ONLY:
        parts.append("/")
    rendered = f"({', '.join(parts)})"
    returned = _annotation(signature.return_annotation)
    return f"{rendered} -> {returned}" if returned else rendered


def _qualified(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def _first_party(obj: Any) -> bool:
    return str(getattr(obj, "__module__", "") or "").partition(".")[0] == "shadowscan"


def _constant_type(value: Any) -> str:
    if isinstance(value, typing.TypeVar):
        return "type-variable"
    if typing.get_origin(value) is not None or isinstance(value, types.UnionType):
        return "type-alias"
    kind = type(value)
    if kind in _BUILTIN_TYPES:
        return kind.__name__
    if _first_party(kind) or kind.__module__ in {"re", "pathlib", "decimal", "datetime"}:
        return _qualified(kind)
    return "object"


def _member(owner: type, name: str, raw: Any) -> dict[str, Any]:
    if isinstance(raw, classmethod | staticmethod):
        return {"kind": type(raw).__name__, "signature": _signature(getattr(owner, name))}
    if isinstance(raw, property):
        return {"kind": "property"}
    if inspect.isfunction(raw):
        kind = "async-method" if inspect.iscoroutinefunction(raw) else "method"
        return {"kind": kind, "signature": _signature(raw)}
    if inspect.isclass(raw):
        return {"kind": "class"}
    return {"kind": "attribute"}


def _class(cls: type) -> dict[str, Any]:
    bases = [_qualified(base) for base in cls.__bases__]
    if issubclass(cls, enum.Enum):
        return {"kind": "enum", "bases": bases, "members": {member.name: member.value for member in cls}}
    described: dict[str, Any] = {
        "kind": "exception" if issubclass(cls, BaseException) else "class",
        "bases": bases,
    }
    # The constructor is recorded when first-party code defines it: an inherited builtin
    # constructor has no signature on some Python versions.
    if any(
        ("__init__" in vars(klass) or "__new__" in vars(klass)) and _first_party(klass)
        for klass in cls.__mro__
        if klass is not object
    ):
        described["signature"] = _signature(cls)
    fields: dict[str, str] = {}
    if dataclasses.is_dataclass(cls):
        fields = {field.name: _annotation(field.type) for field in dataclasses.fields(cls)}
        described["fields"] = fields
    annotations = {
        name: _annotation(value)
        for name, value in inspect.get_annotations(cls).items()
        if not name.startswith("_") and name not in fields
    }
    members = {
        name: _member(cls, name, raw)
        for name, raw in sorted(vars(cls).items())
        if not name.startswith("_") and name not in fields
    }
    for name in sorted(set(annotations) - set(members)):
        members[name] = {"kind": "attribute"}
    for name, member in members.items():
        if member["kind"] == "attribute" and annotations.get(name):
            member["annotation"] = annotations[name]
    described["members"] = dict(sorted(members.items()))
    return described


def _describe(value: Any) -> dict[str, Any]:
    if inspect.isclass(value):
        return _class(value)
    if inspect.isfunction(value) or inspect.isbuiltin(value):
        kind = "async-function" if inspect.iscoroutinefunction(value) else "function"
        return {"kind": kind, "signature": _signature(value)}
    if isinstance(value, types.ModuleType):
        return {"kind": "module"}
    return {"kind": "constant", "type": _constant_type(value)}


def module_names(module: types.ModuleType) -> list[str]:
    """The public names of ``module``: its ``__all__``, or what it defines when it has none."""
    declared = getattr(module, "__all__", None)
    if declared is None:
        return defined_public_names(module)
    return list(declared)


def snapshot() -> dict[str, Any]:
    """The public API as a JSON-ready mapping, modules and names sorted."""
    modules: dict[str, Any] = {}
    for name in public_modules():
        module = importlib.import_module(name)
        names = module_names(module)
        modules[name] = {member: _describe(getattr(module, member)) for member in sorted(names)}
    return {
        "schema": SCHEMA,
        "generated_by": "python -m tools.public_api",
        "modules": modules,
    }


def _leaf(item: dict[str, Any]) -> bool:
    """One line per function, member, constant and enum; classes keep their members on lines of their own."""
    return "kind" in item and item["kind"] not in {"class", "exception"}


def render(data: dict[str, Any] | None = None) -> str:
    return dumps(data if data is not None else snapshot(), leaf=_leaf)


def flatten(data: dict[str, Any]) -> dict[str, Any]:
    """``module.name`` and ``module.Class.member`` keys, so a drift report names what moved."""
    flat: dict[str, Any] = {}
    for module, names in data.get("modules", {}).items():
        for name, described in names.items():
            members = described.get("members") if described.get("kind") != "enum" else None
            flat[f"{module}.{name}"] = {key: value for key, value in described.items() if key != "members"}
            for member, member_described in (members or {}).items():
                flat[f"{module}.{name}.{member}"] = member_described
    return flat


def stale_message(committed: str) -> str | None:
    """None when ``committed`` is the current snapshot, else the drift report to fail with."""
    current = snapshot()
    if committed == render(current):
        return None
    try:
        old = json.loads(committed)
    except ValueError:
        old = {}
    changes = drift(flatten(old if isinstance(old, dict) else {}), flatten(current))
    return drift_report(SNAPSHOT.relative_to(ROOT).as_posix(), "make python-api", changes)


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print("usage: python -m tools.public_api [--check]", file=sys.stderr)
        return 2
    if argv == ["--check"]:
        committed = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.is_file() else ""
        message = stale_message(committed)
        if message is not None:
            print(message, file=sys.stderr)
            return 1
        return 0
    SNAPSHOT.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
