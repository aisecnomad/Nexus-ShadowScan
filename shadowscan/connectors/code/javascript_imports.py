"""Resolve executable JavaScript tool exports from confined, already-read snapshots.

Only relative ES modules and explicit root tsconfig/jsconfig path mappings are
resolved. No packages, source files, configuration extensions or modules are
loaded here. Snapshots belong to one manifest project in one scan root.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from pathlib import PurePosixPath

from shadowscan.connectors.code.python_reexports import project_path
from shadowscan.utils.jsonc import load_json_lenient

JavascriptToolResolver = Callable[[str, str], bool]
ToolExport = bool | tuple[str, str]
MAX_MODULE_BYTES = 65_536
MAX_MODULES = 4096
MAX_EXPORTS = 256
MAX_CHAIN = 16
_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_LOCAL_IMPORT = re.compile(r"\bimport\b")


class JavascriptImportLimit(RuntimeError):
    """A referenced tool module exceeds a static resolution budget."""


def has_javascript_tool_import(text: str) -> bool:
    """Cheap prefilter only; the binder verifies actual imports and call provenance."""
    return bool(re.search(r"\b(?:generateText|streamText)\b", text) and _LOCAL_IMPORT.search(text))


def _confined(path: str) -> str | None:
    if "\\" in path or "\x00" in path or path.startswith("/"):
        return None
    normalized = posixpath.normpath(path)
    return None if normalized == ".." or normalized.startswith("../") else normalized


class JavascriptToolImports:
    """Small named-export graph; ambiguity never proves executable provenance."""

    def __init__(self) -> None:
        self.modules: dict[tuple[str, str], dict[str, ToolExport]] = {}
        self.limited: set[tuple[str, str]] = set()
        self.configs: dict[str, dict[str, list[str]] | None] = {}
        self.ambiguous_configs: set[str] = set()
        # Resolvable aliases and SDK provenance are different facts: ignoring
        # an ambiguous mapping must not make its possible SDK override vanish.
        self.sdk_unknown_scopes: dict[str, set[str]] = {}
        self.sdk_base_urls: dict[str, list[tuple[str, str]]] = {}
        self.observed_sources: set[str] = set()
        self.package_directories: set[str] = set()
        self.full = False

    def add(self, project: str, relative: str, exports: dict[str, ToolExport], *, limited: bool) -> None:
        key = project, project_path(project, relative).as_posix()
        self.note_source(relative)
        if len(self.modules) >= MAX_MODULES:
            self.full = True
            return
        self.modules[key] = exports
        if limited or len(exports) > MAX_EXPORTS:
            self.limited.add(key)
            self.modules[key] = {}

    def add_config(self, project: str, relative: str, text: str) -> None:
        """Read one root config, rejecting ambiguous/inherited resolver settings.

        Multiple root configurations, extends, and multiple target paths remain
        unresolved: deciding their precedence needs a complete compiler resolver.
        """
        document = self._sdk_config(project, relative, text)
        if len(project_path(project, relative).parts) != 1:
            self.ambiguous_configs.add(project)
            self.configs[project] = None
            return
        if project in self.configs or project in self.ambiguous_configs:
            self.configs[project] = None
            return
        self.configs[project] = None
        if not isinstance(document, dict) or "extends" in document:
            return
        options = document.get("compilerOptions", {})
        if not isinstance(options, dict):
            return
        paths = options.get("paths", {})
        base = options.get("baseUrl", ".")
        if not isinstance(paths, dict) or not isinstance(base, str) or _confined(base) is None:
            return
        if len(paths) > MAX_EXPORTS:
            raise JavascriptImportLimit("JavaScript path mapping budget exceeded")
        self.configs[project] = _path_mappings(paths, base)

    def note_package(self, relative: str) -> None:
        """Remember observed package boundaries even when they belong to another project."""
        self.package_directories.add(posixpath.dirname(relative) or ".")

    def note_source(self, relative: str) -> None:
        """A discounted test module can still shadow an SDK through baseUrl."""
        self.observed_sources.add(posixpath.normpath(relative))

    def _sdk_config(self, project: str, relative: str, text: str) -> dict[str, object] | None:
        scope = project_path(project, relative).parent.as_posix()
        unknown = self.sdk_unknown_scopes.setdefault(project, set())
        if len(text.encode("utf-8")) > MAX_MODULE_BYTES:
            unknown.add(scope)
            raise JavascriptImportLimit("JavaScript path configuration budget exceeded")
        try:
            document = load_json_lenient(text)
        except (ValueError, RecursionError):
            unknown.add(scope)
            raise
        if not isinstance(document, dict):
            unknown.add(scope)
            return None
        applies = _configuration_scope(document, scope)
        if _unknown_sdk_config(document):
            unknown.add(applies)
        self._sdk_base(project, scope, applies, document.get("compilerOptions", {}))
        return document

    def _sdk_base(self, project: str, scope: str, applies: str, options: object) -> None:
        if not isinstance(options, dict) or "baseUrl" not in options:
            return
        value = options["baseUrl"]
        base = _confined(posixpath.join(scope, value)) if isinstance(value, str) else None
        if base is None:
            self.sdk_unknown_scopes.setdefault(project, set()).add(applies)
        else:
            self.sdk_base_urls.setdefault(project, []).append((applies, base))

    def _sdk_known(self, project: str, source: str) -> bool:
        if any(_under(source, scope) for scope in self.sdk_unknown_scopes.get(project, ())):
            return False
        return not any(
            _under(source, scope) and self._base_shadows_sdk(project, base)
            for scope, base in self.sdk_base_urls.get(project, ())
        )

    def _base_shadows_sdk(self, project: str, base: str) -> bool:
        path = posixpath.normpath(posixpath.join(project, base, "ai"))
        return path in self.package_directories or any(
            candidate in self.observed_sources for candidate in [*_module_candidates(path), path + ".d.ts"]
        )

    def _mapped(self, project: str, module: str) -> str | None:
        targets: list[str] = []
        for pattern, paths in (self.configs.get(project) or {}).items():
            prefix, star, suffix = pattern.partition("*")
            # The prefix and suffix must not overlap: TypeScript never maps a
            # module shorter than the pattern around its star.
            if (
                star
                and len(module) >= len(prefix) + len(suffix)
                and module.startswith(prefix)
                and module.endswith(suffix)
            ):
                middle = module[len(prefix) : len(module) - len(suffix) if suffix else None]
                targets.extend(path.replace("*", middle) for path in paths)
            elif not star and pattern == module:
                targets.extend(paths)
        return targets[0] if len(targets) == 1 else None

    def _module(self, project: str, consumer: str, module: str) -> str | None:
        path: str | None
        if module.endswith(("/", "/.", "/..")):
            return None
        if module.startswith(("./", "../")):
            path = posixpath.join(posixpath.dirname(consumer), module)
        else:
            path = self._mapped(project, module)
            if path is None:
                return None
        path = _confined(path)
        if path is None:
            return None
        candidates = _module_candidates(path)
        matches = [candidate for candidate in candidates if (project, candidate) in self.modules]
        return matches[0] if len(matches) == 1 else None

    def resolver(self, project: str, relative: str) -> JavascriptToolResolver:
        consumer = project_path(project, relative).as_posix()

        def resolve(module: str, symbol: str) -> bool:
            # A compiler path mapping can replace the SDK itself. Its factory
            # and dispatch names then no longer prove an external AI SDK binding.
            if not self._sdk_known(project, consumer):
                return False
            path = self._module(project, consumer, module)
            if self.full and (module.startswith(("./", "../")) or self._mapped(project, module) is not None):
                raise JavascriptImportLimit("JavaScript imported-tool source budget exceeded")
            seen: set[tuple[str, str]] = set()
            for _ in range(MAX_CHAIN):
                if path is None or (path, symbol) in seen:
                    return False
                if not self._sdk_known(project, path):
                    return False
                seen.add((path, symbol))
                key = project, path
                if self.full or key in self.limited:
                    raise JavascriptImportLimit("JavaScript imported-tool source budget exceeded")
                exported = self.modules.get(key, {}).get(symbol)
                if not isinstance(exported, tuple):
                    return exported is True
                module, symbol = exported
                path = self._module(project, path, module)
            raise JavascriptImportLimit("JavaScript imported-tool chain budget exceeded")

        return resolve


def _under(source: str, scope: str) -> bool:
    return scope == "." or source.startswith(scope + "/")


def _configuration_scope(document: dict[str, object], directory: str) -> str:
    # Inheritance can select files outside the config's directory. Explicit
    # escaping/unknown selections likewise cannot establish a confined scope.
    if "extends" in document:
        return "."
    for key in ("files", "include"):
        values = document.get(key, [])
        if not isinstance(values, list) or any(
            not isinstance(value, str) or _confined(value) is None for value in values
        ):
            return "."
    return directory


def _sdk_pattern(pattern: object) -> bool:
    if not isinstance(pattern, str):
        return True
    # Collapse even invalid repeated stars before checking the two-character
    # SDK name. This preserves uncertainty without creating a regex budget risk.
    collapsed = re.sub(r"\*+", "*", pattern)
    if len(collapsed.replace("*", "")) > 2:
        return False
    return re.fullmatch(re.escape(collapsed).replace(r"\*", ".*"), "ai") is not None


def _unknown_sdk_config(document: dict[str, object]) -> bool:
    if "extends" in document:
        return True
    options = document.get("compilerOptions", {})
    if not isinstance(options, dict):
        return True
    paths = options.get("paths", {})
    return not isinstance(paths, dict) or any(_sdk_pattern(pattern) for pattern in paths)


def _path_mappings(paths: dict[object, object], base: str) -> dict[str, list[str]]:
    mapped: dict[str, list[str]] = {}
    for pattern, targets in paths.items():
        if not isinstance(pattern, str) or pattern.count("*") > 1:
            continue
        if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str):
            continue
        target = targets[0]
        if (
            target.count("*") != pattern.count("*")
            or _confined(target) is None
            or target.endswith(("/", "/.", "/.."))
        ):
            continue
        # Keep the template until _mapped substitutes the complete wildcard:
        # "*/../tools" depends on how many path components the import supplies.
        # _module checks confinement again after substitution and normalization.
        path = posixpath.join(base, target)
        if _confined(path) is not None:
            mapped[pattern] = [path]
    return mapped


def _module_candidates(path: str) -> list[str]:
    suffix = PurePosixPath(path).suffix
    if suffix in _EXTENSIONS:
        # NodeNext commonly imports .js while the checked source is .ts. More
        # than one observed candidate is ambiguous rather than a precedence guess.
        replacements = {".js": (".ts", ".tsx"), ".mjs": (".mts",), ".cjs": (".cts",)}
        return [path, *(path[: -len(suffix)] + ext for ext in replacements.get(suffix, ()))]
    if suffix:
        return []
    return [path + ext for ext in _EXTENSIONS] + [path + "/index" + ext for ext in _EXTENSIONS]
