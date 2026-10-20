"""Generate the machine-readable inventory of every built-in connector.

``docs/connectors/inventory.json`` lists, per connector, what a reviewer needs
before granting it credentials: how it collects, the optional SDK extra and
third-party modules it imports, the credentials it reads, the permission model,
where it connects and the reasons it can leave a scan incomplete. Regenerate it
after changing a connector, its guide or the reviewed data file::

    python -m tools.connector_inventory          # rewrite the inventory (make connector-inventory)
    python -m tools.connector_inventory --check  # exit 1 when it is stale or incomplete

Most of it is derived from the code: class attributes, a static read of the
connector's own modules (imports, ``ctx.get(..., env=...)`` fallbacks, the
diagnostics it records, ``https://`` literals) and the incomplete-reason
classifier the scanner itself uses (``shadowscan.connectors.base.incomplete_reason``).
The permission model is read from the "Least privilege" table of
``docs/connectors.md``. What cannot be derived, which table row applies and
where each connector connects, sits in one reviewed file,
``tools/connector_inventory.yaml``, which :func:`problems` validates against
the code and the guides.
"""

from __future__ import annotations

import ast
import functools
import importlib
import importlib.util
import inspect
import re
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shadowscan.config import _CREDENTIAL_FILE_KEYS, _CREDENTIAL_VALUE_KEYS
from shadowscan.connectors import builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector, incomplete_reason
from shadowscan.utils.redaction_rules import _sensitive_key
from tools.snapshot_json import dumps

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "connectors" / "inventory.json"
DATA = ROOT / "tools" / "connector_inventory.yaml"
OVERVIEW = ROOT / "docs" / "connectors.md"
GUIDES = ROOT / "docs" / "connectors"
SCHEMA = "shadowscan.connector-inventory/v1"

# Framework modules every connector shares. Their failure modes are listed once per source
# (offline input, engine deadline) instead of being read into each connector's own closure.
_SHARED_MODULES = frozenset(
    {
        "shadowscan.connectors",
        "shadowscan.connectors.base",
        "shadowscan.connectors.common",
        "shadowscan.connectors.offline",
    }
)
# Class attributes that hold documentation, whose example URLs are not destinations.
_HELP_ATTRIBUTES = frozenset({"config_keys", "description", "offline_formats", "shared_config_keys"})
# Calls whose first argument is a diagnostic that can leave the scan incomplete.
_DIAGNOSTIC_CALLS = frozenset({"warn", "error", "coverage_gap"})
_RAISERS = frozenset({"ConnectorError", "_raise_connector_error"})
_HTTPS = re.compile(r"https://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?=[/:\"'\s?#]|$)")
# BaseConnector.check_deadline's message: the engine deadline every connector runs under.
DEADLINE_MESSAGE = "connector completion deadline exceeded"
# What a live connector records when the shared HTTPS client (shadowscan.utils.http) fails,
# in the client's words: HttpError("HTTP <status> for <url>") and its connection errors.
HTTP_CLIENT_MESSAGES = (
    "HTTP 401 for https://host/",
    "HTTP 403 for https://host/",
    "HTTP 429 for https://host/",
    "HTTP 500 for https://host/",
    "HTTPS connection timed out",
    "HTTPS connection failed",
)


@dataclass
class Closure:
    """What a static read of one connector's own code found."""

    modules: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    env: dict[str, str] = field(default_factory=dict)
    messages: set[str] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    literals: set[str] = field(default_factory=set)


@functools.cache
def _tree(module: str) -> ast.Module:
    source = inspect.getsource(importlib.import_module(module))
    return ast.parse(source, filename=module)


def _absolute(module: str, node: ast.ImportFrom) -> str:
    """The absolute module an ``import from`` names, resolving relative imports against ``module``."""
    if not node.level:
        return node.module or ""
    parts = str(importlib.import_module(module).__package__).split(".")
    if node.level > 1:
        parts = parts[: -(node.level - 1)]
    return ".".join([*parts, node.module] if node.module else parts)


def _is_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _documentation_ids(tree: ast.AST) -> set[int]:
    """Docstrings and class-level documentation attributes, whose example URLs are not destinations."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
        if isinstance(node, ast.ClassDef):
            for statement in node.body:
                targets = statement.targets if isinstance(statement, ast.Assign) else []
                if isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                if any(isinstance(target, ast.Name) and target.id in _HELP_ATTRIBUTES for target in targets):
                    ids.update(id(child) for child in ast.walk(statement))
    return ids


@functools.cache
def _connects(module: str) -> bool:
    """Whether ``module`` imports a network client: the shared HTTPS client, requests or a cloud SDK."""
    clients = {"shadowscan.utils.http", "requests", "urllib3", "boto3", "botocore", "google", "azure", "oci"}
    for node in ast.walk(_tree(module)):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] in clients for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            target = _absolute(module, node)
            if target in clients or target.split(".")[0] in clients - {"shadowscan"}:
                return True
    return False


def _top_level_names(statement: ast.stmt) -> set[str]:
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {statement.name}
    if isinstance(statement, ast.Assign):
        return {target.id for target in statement.targets if isinstance(target, ast.Name)}
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return {statement.target.id}
    if isinstance(statement, ast.Import | ast.ImportFrom):
        return {(alias.asname or alias.name).split(".")[0] for alias in statement.names}
    return set()


def _scoped_statements(module: str, roots: frozenset[str] | None) -> list[ast.stmt]:
    """Top-level statements of ``module`` that ``roots`` reach by name (every statement when None)."""
    body = _tree(module).body
    if roots is None:
        return list(body)
    wanted = set(roots)
    chosen: set[int] = set()
    grew = True
    while grew:
        grew = False
        for index, statement in enumerate(body):
            if index in chosen or not (_top_level_names(statement) & wanted):
                continue
            chosen.add(index)
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and node.id not in wanted:
                    wanted.add(node.id)
                    grew = True
    return [statement for index, statement in enumerate(body) if index in chosen]


def _imported(module: str, statements: list[ast.stmt]) -> Iterator[tuple[str, frozenset[str] | None]]:
    """``(module, names)`` for every import in ``statements``; names is None for a whole module."""
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield alias.name, None
            elif isinstance(node, ast.ImportFrom):
                target = _absolute(module, node)
                names = set()
                for alias in node.names:
                    if _is_module(f"{target}.{alias.name}"):
                        yield f"{target}.{alias.name}", None
                    else:
                        names.add(alias.name)
                if names:
                    yield target, frozenset(names)


def _own_module(name: str) -> bool:
    """A connector module whose code is read into a connector's closure."""
    return name.startswith("shadowscan.connectors.") and name not in _SHARED_MODULES and _is_module(name)


def _template(node: ast.expr) -> str | None:
    """The fixed text of a diagnostic: a literal, or an f-string's literal parts."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return " ".join(str(part.value) for part in node.values if isinstance(part, ast.Constant))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _template(node.left), _template(node.right)
        return " ".join(text for text in (left, right) if text)
    return None


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _read_call(node: ast.Call, found: Closure) -> None:
    name = _call_name(node)
    keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
    reason = keywords.get("reason")
    if isinstance(reason, ast.Constant) and isinstance(reason.value, str):
        found.reasons.add(reason.value)
    if name in {"get", "require"} and node.args:
        key, env = node.args[0], keywords.get("env")
        if (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and isinstance(env, ast.Constant)
            and isinstance(env.value, str)
        ):
            found.env.setdefault(key.value, env.value)
    elif name == "count_incomplete" and node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.reasons.add(first.value)
    elif (name in _DIAGNOSTIC_CALLS or name in _RAISERS) and node.args:
        text = _template(node.args[0])
        if text:
            found.messages.add(text)


def _read(module: str, statements: list[ast.stmt], found: Closure) -> None:
    skipped = _documentation_ids(_tree(module))
    connects = _connects(module)
    for target, _ in _imported(module, statements):
        top = target.split(".")[0]
        if top in sys.stdlib_module_names or top == "__future__" or not target:
            continue
        if top != "shadowscan":
            found.imports.add(top)
        elif not target.startswith("shadowscan.connectors"):
            found.services.add(target)
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                _read_call(node, found)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skipped:
                found.literals.add(node.value)
                if connects:
                    found.hosts.update(host.lower() for host in _HTTPS.findall(node.value))


def _merge(wanted: dict[str, frozenset[str] | None], module: str, names: frozenset[str] | None) -> bool:
    """Widen what is read of ``module``; True when that added something."""
    if module not in wanted:
        wanted[module] = names
        return True
    current = wanted[module]
    if current is None or (names is not None and names <= current):
        return False
    wanted[module] = None if names is None else current | names
    return True


@functools.cache
def _closure(cls: type[BaseConnector]) -> Closure:
    wanted: dict[str, frozenset[str] | None] = {}
    for klass in cls.__mro__:
        if klass is BaseConnector or not _own_module(klass.__module__):
            continue
        _merge(wanted, klass.__module__, frozenset({klass.__name__}))
    grew = True
    while grew:
        grew = False
        for module, names in list(wanted.items()):
            for target, imported in _imported(module, _scoped_statements(module, names)):
                if _own_module(target) and _merge(wanted, target, imported):
                    grew = True
    found = Closure(modules=set(wanted))
    for module, names in sorted(wanted.items()):
        _read(module, _scoped_statements(module, names), found)
    return found


def closure(cls: type[BaseConnector]) -> Closure:
    """Statically read the code a connector runs.

    Starts from the connector's class bodies (its MRO up to ``BaseConnector``) and
    follows, by name, the module-level code and the connector modules they use:
    ``from module import name`` reads ``name`` and what it reaches, ``import
    module`` reads the module. Shared framework modules (:data:`_SHARED_MODULES`)
    are left out; their failure modes are listed per source. ``https://`` literals
    count as destinations only in modules that import a network client.
    """
    return _closure(cls)


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@functools.cache
def _project() -> tuple[frozenset[str], dict[str, frozenset[str]]]:
    """Core dependency names and the single-provider extras (aws, gcp ...) of ``pyproject.toml``."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    def names(requirements: list[str]) -> frozenset[str]:
        return frozenset(
            _normalized(re.split(r"[\[<>=!~ ;]", requirement, maxsplit=1)[0]) for requirement in requirements
        )

    extras = {
        extra: names(requirements)
        for extra, requirements in project["optional-dependencies"].items()
        if len(requirements) == 1 and not requirements[0].startswith(project["name"])
    }
    return names(project["dependencies"]), extras


def _installed_by(module: str) -> str | None:
    """``core:<distribution>`` or ``extra:<name>`` for a third-party import, from the data file's tables."""
    core, extras = import_tables()
    if module in core:
        return f"core:{core[module]}"
    if module in extras:
        return f"extra:{extras[module]}"
    return None


def _sdk(cls: type[BaseConnector], found: Closure) -> dict[str, Any]:
    imports = [{"module": module, "from": _installed_by(module)} for module in sorted(found.imports)]
    extras = sorted(
        {str(item["from"])[len("extra:") :] for item in imports if str(item["from"]).startswith("extra:")}
    )
    return {
        "requires": list(cls.requires),
        "extras": extras,
        "third_party_imports": imports,
        "first_party_services": sorted(found.services),
    }


def _credentials(cls: type[BaseConnector], found: Closure) -> list[dict[str, Any]]:
    """Configuration keys that hold a credential or name where one is, with their environment fallback."""
    entries = []
    for key in cls.config_keys:
        if key in _CREDENTIAL_FILE_KEYS:
            kind = "credential-file"
        elif key in _CREDENTIAL_VALUE_KEYS or (_sensitive_key(key) and not key.startswith("allow_")):
            kind = "secret"  # an allow_* switch approves a credential source; it holds none
        elif key.endswith("_env"):
            kind = "environment-reference"
        else:
            continue
        entries.append({"key": key, "kind": kind, "env": found.env.get(key)})
    return entries


def _environment(found: Closure) -> list[dict[str, str]]:
    return [{"key": key, "env": env} for key, env in sorted(found.env.items())]


@functools.cache
def _offline_reasons() -> tuple[str, ...]:
    found = Closure()
    _read("shadowscan.connectors.offline", _scoped_statements("shadowscan.connectors.offline", None), found)
    return tuple(sorted({incomplete_reason(text) for text in found.messages} | found.reasons))


def _failure_modes(cls: type[BaseConnector], found: Closure) -> dict[str, Any]:
    by_source: dict[str, list[str]] = {"engine_deadline": [incomplete_reason(DEADLINE_MESSAGE)]}
    if "input" in cls.config_keys:
        by_source["offline_input"] = list(_offline_reasons())
    if "shadowscan.utils.http" in found.services:
        by_source["https_client"] = sorted({incomplete_reason(text) for text in HTTP_CLIENT_MESSAGES})
    own = {incomplete_reason(text) for text in found.messages} | found.reasons
    by_source["connector"] = sorted(own)
    reasons = sorted({reason for values in by_source.values() for reason in values})
    return {"incomplete_reasons": reasons, "by_source": by_source}


def _section(text: str, heading: str) -> str:
    """The body under ``heading`` up to the next heading of the same or a higher level."""
    match = re.search(rf"^{re.escape(heading)}\s*$", text, re.MULTILINE)
    if match is None:
        return ""
    level = len(heading) - len(heading.lstrip("#"))
    rest = text[match.end() :]
    end = re.search(rf"^#{{1,{level}}} ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


@functools.cache
def least_privilege_rows() -> dict[str, str]:
    """``{row label: minimum}`` from the "Least privilege" table of ``docs/connectors.md``."""
    body = _section(OVERVIEW.read_text(encoding="utf-8"), "## Least privilege")
    rows = {}
    for line in body.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] not in {"Connector", "---"} and not set(cells[0]) <= {"-"}:
            rows[cells[0]] = cells[1]
    return rows


def _guides(name: str) -> list[str]:
    """Repository paths and anchors of every guide heading that names the connector."""
    found = []
    for path in [OVERVIEW, *sorted(GUIDES.glob("*.md"))]:
        if path.name == "reference.md":
            continue
        for match in re.finditer(
            rf"^#+ .*`{re.escape(name)}`.*$", path.read_text(encoding="utf-8"), re.MULTILINE
        ):
            found.append(f"{path.relative_to(ROOT).as_posix()}: {match.group(0).lstrip('#').strip()}")
    return found


def _permissions(name: str, cls: type[BaseConnector], entry: dict[str, Any]) -> dict[str, Any]:
    row = entry.get("least_privilege")
    if not cls.live_collection and not row:
        return {
            "model": "offline-export",
            "minimum": "read access to the export given as `input`; no provider credentials",
            "source": "derived: live_collection is False",
            "grants": [],
        }
    if row:
        minimum = least_privilege_rows().get(row, "")
        shared = sorted(
            other
            for other, data in load_data().items()
            if data.get("least_privilege") == row and other != name
        )
        return {
            "model": "least-privilege-table",
            "minimum": minimum,
            "source": f"docs/connectors.md#least-privilege, row {row!r}",
            "grants": sorted(set(re.findall(r"`([^`]+)`", minimum))),
            "shared_with": shared,
            "verify_in_tenant": "verify" in minimum.lower(),
        }
    return {
        "model": "documented-in-data-file",
        "minimum": entry["permissions"],
        "source": "tools/connector_inventory.yaml",
        "grants": [],
    }


def _collection(cls: type[BaseConnector], entry: dict[str, Any]) -> str:
    if not cls.live_collection:
        return "offline-only"
    return "live-api" if entry.get("egress") else "local"


def describe(name: str) -> dict[str, Any]:
    """One connector's inventory entry."""
    cls = get_connector_class(name)
    entry = load_data()[name]
    found = closure(cls)
    return {
        "name": name,
        "class": f"{cls.__module__}:{cls.__qualname__}",
        "surface": cls.surface.value,
        "provider": cls.provider,
        "collection": _collection(cls, entry),
        "offline_input": "input" in cls.config_keys,
        "offline_formats": cls.offline_formats if "input" in cls.config_keys else None,
        "guides": _guides(name),
        "sdk": _sdk(cls, found),
        "credentials": _credentials(cls, found),
        "environment_fallbacks": _environment(found),
        "permissions": _permissions(name, cls, entry),
        "egress": list(entry.get("egress") or []),
        "failure_modes": _failure_modes(cls, found),
    }


@functools.cache
def _data_file() -> dict[str, Any]:
    loaded = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("connectors"), dict):
        raise ValueError(f"{DATA.relative_to(ROOT)} must hold a `connectors:` mapping")
    return loaded


def load_data() -> dict[str, dict[str, Any]]:
    """The reviewed per-connector entries of the data file."""
    return {str(name): dict(entry or {}) for name, entry in _data_file()["connectors"].items()}


def import_tables() -> tuple[dict[str, str], dict[str, str]]:
    """``(core_imports, sdk_imports)``: third-party module to distribution, and to pyproject extra."""
    data = _data_file()
    return dict(data.get("core_imports") or {}), dict(data.get("sdk_imports") or {})


def _import_table_problems() -> Iterator[str]:
    core, extras = _project()
    core_imports, sdk_imports = import_tables()
    for module, distribution in sorted(core_imports.items()):
        if _normalized(distribution) not in core:
            yield f"core_imports: {module} -> {distribution} is not a [project] dependency"
    for module, extra in sorted(sdk_imports.items()):
        if extra not in extras:
            yield f"sdk_imports: {module} -> {extra} is not a single-SDK extra in pyproject.toml"
    for module in sorted(set(core_imports) & set(sdk_imports)):
        yield f"{module} is listed as both a core and an SDK import"


def _egress_problems(
    name: str, cls: type[BaseConnector], entry: dict[str, Any], found: Closure
) -> Iterator[str]:
    egress = entry.get("egress") or []
    not_egress = entry.get("not_egress") or {}
    listed_hosts = set()
    for destination in egress:
        if destination.startswith("<") and destination.endswith(">"):
            if destination[1:-1] not in cls.config_keys:
                yield f"{name}: egress {destination} names no configuration key of the connector"
        elif destination.startswith("sdk:"):
            if destination[4:] not in found.imports:
                yield f"{name}: egress {destination} names a module the connector does not import"
        elif destination.startswith("discovered:"):
            if not destination[len("discovered:") :].strip():
                yield f"{name}: egress {destination!r} must say where the discovered destination comes from"
        elif destination.startswith("*"):
            if not any(destination[1:] in literal for literal in found.literals):
                yield f"{name}: egress {destination} matches no string in the connector's code"
        else:
            listed_hosts.add(destination)
            if destination not in found.hosts:
                yield f"{name}: egress host {destination} is not an https:// literal in the connector's code"
    for host in sorted(found.hosts - listed_hosts - set(not_egress)):
        yield (
            f"{name}: the code names https://{host}; list it under egress, or under not_egress with the "
            "reason it is never contacted"
        )
    for host in sorted(set(not_egress) - found.hosts):
        yield f"{name}: not_egress lists {host}, which the connector's code no longer names"
    if cls.live_collection and "shadowscan.utils.http" in found.services and not egress:
        yield f"{name}: uses the HTTPS client but lists no egress"
    if not cls.live_collection and egress:
        yield f"{name}: an offline-only connector lists egress"


def problems() -> list[str]:
    """Why the reviewed data file does not describe the registered connectors, or []."""
    data = load_data()
    registered = set(builtin_connector_names())
    found_problems = [
        f"{name}: registered but has no entry in {DATA.name}" for name in sorted(registered - set(data))
    ]
    found_problems += [
        f"{name}: listed in {DATA.name} but not registered" for name in sorted(set(data) - registered)
    ]
    rows = least_privilege_rows()
    found_problems += list(_import_table_problems())
    allowed = {"least_privilege", "permissions", "egress", "not_egress"}
    for name in sorted(registered & set(data)):
        cls = get_connector_class(name)
        entry = data[name]
        found_problems += [f"{name}: unknown field {key}" for key in sorted(set(entry) - allowed)]
        row = entry.get("least_privilege")
        if cls.live_collection and row is None and not entry.get("permissions"):
            found_problems.append(
                f"{name}: live connector needs a least_privilege row or a permissions statement"
            )
        if not cls.live_collection and entry.get("permissions"):
            found_problems.append(
                f"{name}: an offline-only connector reads an export; drop its permissions statement"
            )
        if row is not None and row not in rows:
            found_problems.append(
                f"{name}: no row {row!r} in the Least privilege table of docs/connectors.md"
            )
        if row is not None and entry.get("permissions"):
            found_problems.append(f"{name}: give a least_privilege row or a permissions statement, not both")
        if not _guides(name):
            found_problems.append(f"{name}: no guide heading under docs/connectors names it")
        found = closure(cls)
        found_problems += list(_egress_problems(name, cls, entry, found))
        found_problems += [
            f"{name}: imports {module}, which neither core_imports nor sdk_imports lists"
            for module in sorted(found.imports)
            if _installed_by(module) is None
        ]
        unknown = sorted(found.reasons - set(_known_reasons()))
        if unknown:
            found_problems.append(f"{name}: records unknown incomplete reasons {unknown}")
    unused = sorted(set(rows) - {entry.get("least_privilege") for entry in data.values()})
    found_problems += [f"Least privilege row {row!r} is mapped to no connector" for row in unused]
    return found_problems


def _known_reasons() -> tuple[str, ...]:
    from shadowscan.coverage import INCOMPLETE_REASONS

    return INCOMPLETE_REASONS


def inventory() -> dict[str, Any]:
    names = sorted(builtin_connector_names())
    connectors = [describe(name) for name in names]
    return {
        "schema": SCHEMA,
        "generated_by": "python -m tools.connector_inventory",
        "connector_count": len(connectors),
        "needs_tenant_verification": sorted(
            entry["name"] for entry in connectors if entry["permissions"].get("verify_in_tenant")
        ),
        "connectors": connectors,
    }


def _leaf(item: dict[str, Any]) -> bool:
    """One line per import and per credential or environment entry."""
    return set(item) in ({"module", "from"}, {"key", "kind", "env"}, {"key", "env"})


def render(data: dict[str, Any] | None = None) -> str:
    return dumps(data if data is not None else inventory(), leaf=_leaf)


def stale_message(committed: str) -> str | None:
    """None when the data file is complete and ``committed`` is current, else why not."""
    issues = problems()
    if issues:
        return f"{DATA.relative_to(ROOT)} does not describe the connectors:\n  " + "\n  ".join(issues)
    if committed != render():
        return f"{INVENTORY.relative_to(ROOT)} is stale; run `make connector-inventory` and commit the result"
    return None


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print("usage: python -m tools.connector_inventory [--check]", file=sys.stderr)
        return 2
    if argv == ["--check"]:
        committed = INVENTORY.read_text(encoding="utf-8") if INVENTORY.is_file() else ""
        message = stale_message(committed)
        if message is not None:
            print(message, file=sys.stderr)
            return 1
        return 0
    issues = problems()
    if issues:
        print("\n".join(issues), file=sys.stderr)
        return 1
    INVENTORY.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
