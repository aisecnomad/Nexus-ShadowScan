"""Resolve direct AI SDK tool imports using only already-read project sources.

Only stable named imports of explicit exported ``const name = tool({execute})``
are resolved. The factory and generation call must bind to ``ai``. Relative
paths and one-target tsconfig/jsconfig path mappings stay inside one manifest
project; ambiguous files, re-exports, inheritance and dynamic aliases stay
opaque. No code is loaded or executed and this module never opens a path.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import replace
from pathlib import PurePosixPath

from shadowscan.connectors.code.javascript_reachability import (
    JavascriptReachabilityLimit,
    _Token,
    _tokens,
)
from shadowscan.connectors.code.javascript_tool_attribution import _Tools
from shadowscan.connectors.code.python_reexports import project_path
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import (
    SourceBudgetExceeded,
    _Binding,
    _Call,
    _drop_uncertain_bindings,
    _javascript_bindings,
    _javascript_module_level,
)
from shadowscan.connectors.code.vercel_tools import (
    _execution_callback,
    _literal,
    _object,
    _unwrap,
    has_executable_vercel_tools,
)
from shadowscan.signatures import Match, Signal, SignatureIndex
from shadowscan.signatures.matcher import pattern_timeout
from shadowscan.utils.jsonc import load_json_lenient

MAX_MODULES = 4096
MAX_SOURCE_BYTES = 262_144
MAX_CONFIG_BYTES = 65_536
MAX_IMPORTS = 256
_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"})
_CONFIGS = frozenset({"tsconfig.json", "jsconfig.json"})
_NAME = re.compile(r"[A-Za-z_$][\w$]*\Z")
_LOCAL_IMPORT = re.compile(r"\bimport\b[^;]{0,2000}\bfrom\s*['\"](?:\./|\.\./|[^'\"\n]+/)")


def has_local_tool_import(text: str) -> bool:
    """Cheap prefilter; binding, path resolution and callback proof run later."""
    return bool(re.search(r"\b(?:generateText|streamText)\b", text) and _LOCAL_IMPORT.search(text))


def has_ai_sdk_import(text: str) -> bool:
    """Queue SDK source until project configuration can resolve its module name."""
    return bool(re.search(r"\b(?:from\s*|require\s*\(\s*)['\"]ai['\"]", text))


def without_ai_sdk_proof(matches: list[Match]) -> list[Match]:
    """Retain SDK references while withholding unverifiable agent/capability claims."""
    result: list[Match] = []
    for match in matches:
        if match.signature_id != "framework.vercel-ai-sdk":
            result.append(match)
            continue
        extra = {
            **match.extra,
            "verified_agent": False,
            "source_capabilities": [],
            "sdk_module_unresolved": True,
        }
        extra.pop("registered_tool_regions", None)
        extra.pop("registered_tool_declarations", None)
        signal = match.signal
        if signal.type == "code":
            signal = replace(
                signal,
                agent_indicator=False,
                capabilities=[],
                description="AI SDK reference with unresolved project module provenance",
            )
        result.append(replace(match, signal=signal, extra=extra))
    return result


def _mask(text: str, spans: Sequence[tuple[int, int]]) -> str:
    pieces: list[str] = []
    previous = 0
    for start, end in spans:
        pieces.extend((text[previous:start], re.sub(r"[^\r\n]", " ", text[start:end])))
        previous = end
    pieces.append(text[previous:])
    return "".join(pieces)


def _path(path: PurePosixPath) -> str | None:
    """Normalize a relative import without allowing escape from its project."""
    if path.is_absolute() or "\\" in str(path):
        return None
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts) if parts else None


def _named_import(tokens: list[_Token], opening: int) -> tuple[list[tuple[str, str]], int]:
    """Read the supported named specifiers of one bounded tokenized import."""
    cursor = opening + 1
    names: list[tuple[str, str]] = []
    while cursor < len(tokens) and tokens[cursor].value != "}":
        source = tokens[cursor]
        if source.literal or not _NAME.fullmatch(source.value) or source.value == "type":
            return [], len(tokens)
        local = source.value
        cursor += 1
        if cursor < len(tokens) and tokens[cursor].value == "as":
            cursor += 1
            if cursor >= len(tokens) or tokens[cursor].literal or not _NAME.fullmatch(tokens[cursor].value):
                return [], len(tokens)
            local = tokens[cursor].value
            cursor += 1
        names.append((local, source.value))
        if cursor < len(tokens) and tokens[cursor].value == ",":
            cursor += 1
        elif cursor >= len(tokens) or tokens[cursor].value != "}":
            return [], len(tokens)
    return names, cursor


def _imports(
    text: str, masked: str, tokens: list[_Token]
) -> tuple[dict[str, _Binding], list[tuple[int, int]]]:
    """Read only complete, module-level named ES imports, rejecting duplicates."""
    bindings: dict[str, _Binding] = {}
    duplicates: set[str] = set()
    spans: list[tuple[int, int]] = []
    for position, token in enumerate(tokens):
        if not position % 256:
            pattern_timeout()
        if token.literal or token.value != "import" or not _javascript_module_level(masked, token.start):
            continue
        cursor = position + 1
        if cursor >= len(tokens) or tokens[cursor].value != "{":
            continue
        names, cursor = _named_import(tokens, cursor)
        if (
            cursor + 2 >= len(tokens)
            or tokens[cursor].value != "}"
            or tokens[cursor + 1].value != "from"
            or not tokens[cursor + 2].literal
        ):
            continue
        module = _literal(tokens[cursor + 2].value)
        if module is None or len(module) > 240:
            continue
        spans.append((token.start, tokens[cursor + 2].end))
        for local, symbol in names:
            if local in bindings:
                duplicates.add(local)
            bindings[local] = _Binding(module, symbol)
        if len(bindings) > MAX_IMPORTS:
            raise SourceBudgetExceeded("JavaScript project tool import limit exceeded")
    _drop_uncertain_bindings(bindings, masked, spans)
    for name in duplicates:
        bindings.pop(name, None)
    return bindings, spans


def _exports(text: str, ignored: list[tuple[int, int]]) -> frozenset[str]:
    calls, _ = _javascript_bindings(text, ignored, lambda binding: binding.module == "ai")
    factories = {
        (call.start, call.end): call
        for call in calls
        if call.binding.module == "ai" and call.binding.symbol == "tool" and not call.partial
    }
    if not factories:
        return frozenset()
    masked = _mask(text, ignored)
    tokens = _tokens(text, masked, ignored)
    tools = _Tools(text, masked, tokens, list(factories), tokens)
    exports: set[str] = set()
    for name, definition in tools.definitions.items():
        first, last = definition.value
        declaration = definition.declaration[0]
        if definition.function or declaration < 2 or tokens[declaration - 2].value != "export":
            continue
        call = factories.get((tokens[first].start, tokens[last - 1].end))
        if call is None or not tools.stable(definition, descriptor=True):
            continue
        arguments = _unwrap(call.arguments, call.structural_arguments, "(")
        fields = _object(*arguments) if arguments else None
        if fields and "execute" in fields and _execution_callback(*fields["execute"]):
            exports.add(name)
    return frozenset(exports)


def _selected_imports(
    text: str,
    ignored: list[tuple[int, int]],
    calls: list[_Call],
) -> dict[str, _Binding]:
    masked = _mask(text, ignored)
    tokens = _tokens(text, masked, ignored)
    bindings, import_spans = _imports(text, masked, tokens)
    if not bindings:
        return {}
    tools = _Tools(text, masked, tokens, [], tokens)
    allowed: set[int] = set()
    for call in calls:
        for first, last in tools.constructor_entries((call.start, call.end)):
            if last - first == 1:
                allowed.add(tokens[first].start)
                # An explicitly named tool map entry may repeat the imported
                # identifier as its property key: { lookup: lookup }.
                if first >= 2 and tokens[first - 1].value == ":":
                    allowed.add(tokens[first - 2].start)
    starts = [start for start, _ in import_spans]
    for token in tokens:
        if token.literal or token.value not in bindings or token.start in allowed:
            continue
        position = bisect_right(starts, token.start) - 1
        if position < 0 or token.start >= import_spans[position][1]:
            # An escaped descriptor could be mutated by arbitrary local code.
            bindings.pop(token.value, None)
    return bindings


class JavascriptProjectTools:
    """Bounded export/configuration catalog scoped to a single filesystem scan."""

    def __init__(self) -> None:
        self.paths: set[tuple[str, str]] = set()
        self.exports: dict[tuple[str, str], frozenset[str]] = {}
        self.aliases: dict[tuple[str, str], dict[str, str | None] | None] = {}
        self.base_urls: set[tuple[str, str]] = set()
        self.full = False

    def note_path(self, project: str, relative: str) -> None:
        path = project_path(project, relative)
        if path.suffix not in _EXTENSIONS and path.name not in _CONFIGS:
            return
        key = (project, str(path))
        if key in self.paths:
            return
        if len(self.paths) >= MAX_MODULES:
            self.full = True
            return
        self.paths.add(key)

    def add(self, project: str, relative: str, text: str, ext: str) -> None:
        """Record a scanned module or configuration; never read additional files."""
        path = project_path(project, relative)
        self.note_path(project, relative)
        if self.full:
            # Ordinary source scanning remains useful without this optional
            # index. Its limit becomes a coverage gap only for consumers that
            # actually need cross-file resolution, in matches().
            return
        key = (project, str(path))
        if path.name in _CONFIGS:
            if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
                raise SourceBudgetExceeded("JavaScript project tool configuration limit exceeded")
            self.aliases[key] = self._aliases(text, path.parent)
            try:
                config = load_json_lenient(text)
            except (ValueError, RecursionError):
                config = None
            if isinstance(config, dict) and isinstance(config.get("compilerOptions"), dict):
                if "baseUrl" in config["compilerOptions"]:
                    self.base_urls.add(key)
        elif (
            ext in _EXTENSIONS
            and re.search(r"\bexport\s+const\b", text)
            and re.search(r"\btool\b", text)
            and re.search(r"\bfrom\s*['\"]ai['\"]", text)
        ):
            if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
                raise SourceBudgetExceeded("JavaScript project tool source limit exceeded")
            ignored, ambiguous = noncode_ranges(text, "javascript", ext, jsx=ext in {".jsx", ".tsx"})
            if not ambiguous:
                try:
                    self.exports[key] = _exports(text, ignored)
                except JavascriptReachabilityLimit as exc:
                    raise SourceBudgetExceeded(str(exc)) from exc
                except ValueError:
                    # Unbalanced or unsupported declarations cannot prove a
                    # stable exported descriptor. The ordinary binder reports
                    # its own parse diagnostics for this file.
                    return

    @staticmethod
    def _aliases(text: str, parent: PurePosixPath) -> dict[str, str | None] | None:
        try:
            document = load_json_lenient(text)
        except (ValueError, RecursionError):
            return None
        if not isinstance(document, dict) or "extends" in document or "references" in document:
            return None
        options = document.get("compilerOptions", {})
        if not isinstance(options, dict):
            return None
        base = options.get("baseUrl", ".")
        paths = options.get("paths", {})
        if not isinstance(base, str) or not isinstance(paths, dict):
            return None
        if len(paths) > MAX_IMPORTS:
            raise SourceBudgetExceeded("JavaScript project tool path mapping limit exceeded")
        aliases: dict[str, str | None] = {}
        for pattern, targets in paths.items():
            if not isinstance(pattern, str) or pattern.count("*") > 1:
                continue
            # An unsupported stronger pattern must still mask a supported
            # wildcard; otherwise uncertainty could resolve the wrong file.
            aliases[pattern] = None
            if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str):
                continue
            target = targets[0]
            if target.count("*") != pattern.count("*") or "\\" in pattern:
                continue
            template = parent / base / target
            # Normalize only after substituting the wildcard. A '*' may stand
            # for several segments, so collapsing '*/..' here changes meaning.
            if not template.is_absolute() and "\\" not in str(template):
                aliases[pattern] = str(template)
        return aliases

    def _config_key(self, project: str, source: PurePosixPath) -> tuple[str, str] | None:
        for parent in source.parents:
            available = [
                (project, str(parent / name))
                for name in _CONFIGS
                if (project, str(parent / name)) in self.paths
            ]
            if available:
                # Two configurations or an unread/malformed nearer config
                # cannot safely inherit a more distant alias mapping.
                return available[0] if len(available) == 1 else (project, "")
        return None

    def _config(self, project: str, source: PurePosixPath) -> dict[str, str | None] | None:
        key = self._config_key(project, source)
        return self.aliases.get(key) if key is not None else {}

    def ai_sdk_is_external(self, project: str, relative: str) -> bool:
        """Whether project configuration permits an import of ai to mean the SDK.

        Inherited/unread configuration and baseUrl package lookup are opaque.
        A path mapping that can replace ai invalidates SDK proof even when its
        target was not read or its fallback list is unsupported.
        """
        if self.full:
            return False
        source = project_path(project, relative)
        config = self._config(project, source)
        if config is None or self._config_key(project, source) in self.base_urls:
            return False
        for alias in config:
            prefix, star, suffix = alias.partition("*")
            if alias == "ai" or star and "ai".startswith(prefix) and "ai".endswith(suffix):
                return False
        return True

    def _target(self, project: str, source: str, module: str) -> str | None:
        path = PurePosixPath(source)
        if module.startswith(("./", "../")):
            base = _path(path.parent / module)
        else:
            matches: list[tuple[int, str | None]] = []
            for alias, target in (self._config(project, path) or {}).items():
                prefix, star, suffix = alias.partition("*")
                if not star:
                    if module == alias:
                        matches.append((len(alias) + 1, target))
                elif (
                    module.startswith(prefix)
                    and module.endswith(suffix)
                    and len(module) >= len(prefix + suffix)
                ):
                    value = module[len(prefix) : len(module) - len(suffix) if suffix else None]
                    matches.append((len(prefix), target.replace("*", value) if target is not None else None))
            if not matches:
                return None
            strongest = max(rank for rank, _ in matches)
            targets = {target for rank, target in matches if rank == strongest}
            target = next(iter(targets)) if len(targets) == 1 else None
            base = _path(PurePosixPath(target)) if target is not None else None
        if base is None:
            return None
        candidate = PurePosixPath(base)
        if candidate.suffix in _EXTENSIONS:
            candidates = {base}
            # TypeScript resolves explicit emitted JS paths to source TS.
            if candidate.suffix in {".js", ".mjs", ".cjs"}:
                replacement = {".js": ".ts", ".mjs": ".mts", ".cjs": ".cts"}[candidate.suffix]
                candidates.add(str(candidate.with_suffix(replacement)))
        elif candidate.suffix:
            return None
        else:
            candidates = {base + extension for extension in _EXTENSIONS}
            candidates.update(str(candidate / ("index" + extension)) for extension in _EXTENSIONS)
        existing = [value for value in candidates if (project, value) in self.paths]
        return existing[0] if len(existing) == 1 else None

    def matches(
        self,
        index: SignatureIndex,
        project: str,
        relative: str,
        text: str,
        ignored: list[tuple[int, int]],
    ) -> list[Match]:
        """Prove selected local descriptors and return call-specific agent evidence."""
        if self.full:
            raise SourceBudgetExceeded("JavaScript project tool module limit exceeded")
        if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise SourceBudgetExceeded("JavaScript project tool consumer limit exceeded")
        signature = index.signatures.get("framework.vercel-ai-sdk")
        if signature is None or not self.ai_sdk_is_external(project, relative):
            return []
        calls, _ = _javascript_bindings(text, ignored, lambda binding: binding.module == "ai")
        selected = [
            call
            for call in calls
            if call.binding.module == "ai"
            and call.binding.symbol in {"generateText", "streamText"}
            and not call.partial
        ]
        if not selected:
            return []
        try:
            bindings = _selected_imports(text, ignored, selected)
        except JavascriptReachabilityLimit as exc:
            raise SourceBudgetExceeded(str(exc)) from exc
        except ValueError:
            return []
        source = str(project_path(project, relative))
        names = {
            local
            for local, binding in bindings.items()
            if (target := self._target(project, source, binding.module)) is not None
            and self.ai_sdk_is_external(project, str(PurePosixPath(project) / target))
            and binding.symbol in self.exports.get((project, target), ())
        }
        result: list[Match] = []
        for call in selected:
            if not names or not has_executable_vercel_tools(
                call.arguments, call.structural_arguments, (), executable_names=names, named_only=True
            ):
                continue
            result.append(
                Match(
                    signature,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        capabilities=["tool-use"],
                        description="import-bound AI SDK dispatch to a resolved local executable tool",
                    ),
                    f"ai:{call.binding.symbol}(",
                    0.9,
                    line=call.line,
                    extra={
                        "verified_agent": True,
                        "source_capabilities": ["tool-use"],
                        "bound_call_span": (call.start, call.end),
                        "configured_call_span": (call.start, call.end),
                    },
                )
            )
        return result
