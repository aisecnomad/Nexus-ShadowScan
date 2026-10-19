"""Bounded, source-only resolution of local Python tool dispatch helpers.

The index consumes source already read by the confined filesystem connector. It
never imports modules or opens files. Recognition is deliberately narrow: a
literal table of local file-reading functions, or name-selected HTTP requests
through a resolved httpx client. This is declared source flow, not proof that a
request or local function ran. Unsupported programs provide no dispatch proof.
Limits are attached to affected modules and raised only when they are resolved.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import PurePosixPath

from shadowscan.connectors.code.python_reexports import project_path
from shadowscan.signatures.matcher import pattern_timeout

MAX_FILES = 1_024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_AST_NODES = 100_000
MAX_TOTAL_NODES = 500_000
_FROM_IMPORT = re.compile(r"(?m)^[ \t\f]*from[ \t\f]+([.\w]+)[ \t\f]+import[ \t\f]+(?=[\w(])")


class DispatchLimitError(ValueError):
    """A requested helper could not be fully indexed within the scan budget."""


def _nodes(tree: ast.AST) -> Iterator[ast.AST]:
    pending = [tree]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_AST_NODES:
            raise DispatchLimitError("Python dispatch AST node budget exceeded")
        if count % 256 == 0:
            pattern_timeout()
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _assignment(node: ast.stmt) -> tuple[str, ast.expr] | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        if isinstance(node.targets[0], ast.Name):
            return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    return None


def _docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _parameters(function: ast.FunctionDef) -> list[str] | None:
    args = function.args
    if function.decorator_list or args.vararg or args.kwarg or args.kwonlyargs or args.defaults:
        return None
    names = [arg.arg for arg in (*args.posonlyargs, *args.args)]
    return names if len(names) == len(set(names)) else None


def _unmutated(function: ast.FunctionDef, protected: set[str]) -> bool:
    for node in _nodes(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in protected:
                return False
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if _root(node) in protected:
                return False
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom)):
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not function:
            return False
        if isinstance(node, ast.ExceptHandler) and node.name in protected:
            return False
    return True


def _contains(node: ast.AST, name: str) -> bool:
    return any(isinstance(part, ast.Name) and part.id == name for part in _nodes(node))


def _guard(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == name
        and len(node.ops) == len(node.comparators) == 1
        and isinstance(node.ops[0], ast.Eq)
        and isinstance(node.comparators[0], ast.Constant)
        and isinstance(node.comparators[0].value, str)
        and bool(node.comparators[0].value)
    )


def _inert(node: ast.AST) -> bool:
    """Literal/parameter expressions cannot hide arbitrary calls or binding changes."""
    conditional = (ast.IfExp, ast.BoolOp, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    return not any(
        isinstance(part, (ast.Call, ast.NamedExpr, ast.Lambda, *conditional)) for part in _nodes(node)
    )


class _Module:
    def __init__(self, tree: ast.Module, local_roots: set[str]) -> None:
        self.local_roots = local_roots
        self.functions: dict[str, ast.FunctionDef] = {}
        self.imports: dict[str, str] = {}
        self.paths: set[str] = set()
        self.bindings: Counter[str] = Counter()
        self.valid = self._declarations(tree)
        if self.valid:
            self.valid = self._initializers(tree)
        if self.valid:
            self._path_constants(tree)

    def _declarations(self, tree: ast.Module) -> bool:
        for statement in tree.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                if not self._import(statement):
                    return False
            elif isinstance(statement, ast.FunctionDef):
                self.bindings[statement.name] += 1
                self.functions[statement.name] = statement
            elif pair := _assignment(statement):
                self.bindings[pair[0]] += 1
            elif not _docstring(statement):
                # Import-time branches, mutation and execution can replace bindings.
                return False
        return True

    def _initializers(self, tree: ast.Module) -> bool:
        for statement in tree.body:
            if pair := _assignment(statement):
                for node in _nodes(pair[1]):
                    if isinstance(node, ast.NamedExpr):
                        return False
                    if isinstance(node, ast.Call) and self.target(node.func) not in {
                        "pathlib.Path",
                        "os.environ.get",
                        "os.getenv",
                    }:
                        return False
        return True

    def _import(self, statement: ast.Import | ast.ImportFrom) -> bool:
        for alias in statement.names:
            if alias.name == "*":
                return False
            local = alias.asname or alias.name.split(".")[0]
            self.bindings[local] += 1
            if isinstance(statement, ast.Import):
                self.imports[local] = alias.name if alias.asname else local
            elif statement.module and not statement.level:
                self.imports[local] = f"{statement.module}.{alias.name}"
        return True

    def target(self, node: ast.AST) -> str:
        dotted = _dotted(node)
        root, _, suffix = dotted.partition(".")
        if self.bindings[root] != 1 or root not in self.imports:
            return ""
        return self.imports[root] + (f".{suffix}" if suffix else "")

    def _path_constants(self, tree: ast.Module) -> None:
        for statement in tree.body:
            pair = _assignment(statement)
            if pair is None:
                continue
            name, value = pair
            if self.bindings[name] == 1 and isinstance(value, ast.Call):
                if self.target(value.func) == "pathlib.Path":
                    self.paths.add(name)

    def dispatches(self, symbol: str) -> bool:
        function = self.functions.get(symbol)
        if not self.valid or function is None or self.bindings[symbol] != 1:
            return False
        if any(target.split(".")[0] in self.local_roots for target in self.imports.values()):
            return False
        params = _parameters(function)
        if params is None or len(params) != 2:
            return False
        protected = set(params) | set(self.imports) | self.paths | set(self.functions)
        if not _unmutated(function, protected):
            return False
        if any(
            isinstance(node, (ast.Global, ast.Nonlocal))
            for f in self.functions.values()
            for node in _nodes(f)
        ):
            return False
        return _Dispatcher(self, *params).block(function.body)

    def file_handler(self, name: str) -> bool:
        function = self.functions.get(name)
        if function is None or self.bindings[name] != 1:
            return False
        params = _parameters(function)
        if params is None:
            return False
        protected = set(self.imports) | self.paths
        if not _unmutated(function, protected):
            return False
        return _file_body(function.body, self.paths - set(params))


def _path_value(value: ast.AST, paths: set[str]) -> bool:
    if isinstance(value, ast.Name):
        return value.id in paths
    return isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div) and _path_value(value.left, paths)


def _path_call(value: ast.AST, paths: set[str], methods: set[str]) -> bool:
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr in methods
        and _path_value(value.func.value, paths)
    )


def _file_statement(statement: ast.stmt, paths: set[str]) -> bool:
    if isinstance(statement, (ast.Return, ast.Assign, ast.AnnAssign)):
        if statement.value is not None and _file_expression(statement.value, paths):
            return True
    if isinstance(statement, ast.For):
        if _file_expression(statement.iter, paths):
            return True
        inner_paths = set(paths)
        if isinstance(statement.target, ast.Name) and _path_call(statement.iter, paths, {"glob", "rglob"}):
            inner_paths.add(statement.target.id)
        return _file_body(statement.body, inner_paths)
    if isinstance(statement, ast.If):
        if isinstance(statement.test, ast.Constant):
            return _file_body(statement.body if statement.test.value else statement.orelse, set(paths))
        return _file_body(statement.body, set(paths)) or _file_body(statement.orelse, set(paths))
    return False


def _file_expression(value: ast.AST, paths: set[str]) -> bool:
    """Only eagerly evaluated expression positions can establish file access."""
    if _path_call(value, paths, {"read_text", "read_bytes", "glob", "rglob"}):
        return True
    if isinstance(value, ast.Call):
        return _file_expression(value.func, paths) or any(
            _file_expression(argument, paths) for argument in value.args
        )
    if isinstance(value, (ast.Attribute, ast.Subscript)):
        return _file_expression(value.value, paths)
    if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp)):
        return bool(value.generators) and _file_expression(value.generators[0].iter, paths)
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return any(_file_expression(element, paths) for element in value.elts)
    return False


def _file_body(statements: list[ast.stmt], paths: set[str]) -> bool:
    for statement in statements:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.If, ast.For, ast.Return)):
            if _docstring(statement):
                continue
            return False
        # Conditional assignments and string-valued capture bindings cannot
        # preserve an earlier Path alias.
        for node in _nodes(statement):
            if bound := _bound_name(node):
                paths.discard(bound)
        if pair := _assignment(statement):
            name, value = pair
            if _path_value(value, paths):
                paths.add(name)
            else:
                paths.discard(name)
        if _file_statement(statement, paths):
            return True
        if _always_stops(statement):
            break
    return False


def _bound_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return node.id
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    return None


def _always_stops(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
        chosen = statement.body if statement.test.value else statement.orelse
        return any(_always_stops(child) for child in chosen)
    return False


class _Dispatcher:
    def __init__(self, module: _Module, name: str, args: str) -> None:
        self.module, self.name, self.args = module, name, args
        self.table: str | None = None

    def _table_assignment(self, statement: ast.stmt) -> bool:
        pair = _assignment(statement)
        if pair is None or self.table is not None:
            return False
        name, value = pair
        if not isinstance(value, ast.Dict) or not value.keys:
            return False
        keys: set[str] = set()
        for key, handler in zip(value.keys, value.values, strict=True):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or key.value in keys:
                return False
            if not isinstance(handler, ast.Name) or not self.module.file_handler(handler.id):
                return False
            keys.add(key.value)
        self.table = name
        return True

    def _table_return(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Call) and self.module.target(value.func) == "json.dumps":
            if len(value.args) != 1 or value.keywords:
                return False
            value = value.args[0]
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Subscript):
            return False
        selected = value.func
        return (
            isinstance(selected.value, ast.Name)
            and selected.value.id == self.table
            and isinstance(selected.slice, ast.Name)
            and selected.slice.id == self.name
            and not value.args
            and len(value.keywords) == 1
            and value.keywords[0].arg is None
            and isinstance(value.keywords[0].value, ast.Name)
            and value.keywords[0].value.id == self.args
        )

    def _missing_guard(self, statement: ast.If) -> bool:
        test = statement.test
        if not (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == self.name
            and len(test.ops) == len(test.comparators) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and isinstance(test.comparators[0], ast.Name)
            and test.comparators[0].id == self.table
            and not statement.orelse
        ):
            return False
        return len(statement.body) == 1 and isinstance(statement.body[0], ast.Return)

    def block(self, statements: list[ast.stmt]) -> bool:
        for statement in statements:
            if _docstring(statement) or self._table_assignment(statement):
                continue
            if isinstance(statement, ast.Return):
                return statement.value is not None and self._table_return(statement.value)
            if isinstance(statement, ast.If) and self._missing_guard(statement):
                continue
            if isinstance(statement, ast.Try):
                if statement.finalbody or statement.orelse:
                    return False
                return self.block(statement.body)
            if isinstance(statement, ast.With):
                return self._http_context(statement)
            return False
        return False

    def _http_context(self, statement: ast.With) -> bool:
        if len(statement.items) != 1:
            return False
        item = statement.items[0]
        call = item.context_expr
        if not isinstance(item.optional_vars, ast.Name) or not isinstance(call, ast.Call):
            return False
        if self.module.target(call.func) != "httpx.Client":
            return False
        if any(not _inert(argument) for argument in call.args):
            return False
        if any(not _inert(keyword.value) for keyword in call.keywords):
            return False
        client = item.optional_vars.id
        if client in {self.name, self.args} | set(self.module.imports):
            return False
        return self._http_branches(statement.body, client)

    def _http_branches(self, statements: list[ast.stmt], client: str) -> bool:
        found = False
        for statement in statements:
            if not isinstance(statement, ast.If) or not _guard(statement.test, self.name):
                return False
            if statement.orelse or not self._http_result(statement.body, client):
                return False
            found = True
        return found

    def _http_request(self, node: ast.AST, client: str) -> bool:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            return False
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != client:
            return False
        if node.func.attr not in {"get", "post", "put", "patch", "delete"}:
            return False
        values = [*node.args, *(keyword.value for keyword in node.keywords)]
        return all(_inert(value) for value in values) and any(_contains(value, self.args) for value in values)

    def _http_result(self, body: list[ast.stmt], client: str) -> bool:
        if len(body) == 1 and isinstance(body[0], ast.Return):
            value = body[0].value
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
                return False
            return (
                value.func.attr == "json"
                and not value.args
                and not value.keywords
                and self._http_request(value.func.value, client)
            )
        if len(body) != 2 or not isinstance(body[1], ast.Return) or body[1].value is None:
            return False
        pair = _assignment(body[0])
        if pair is None or pair[0] in {self.name, self.args, client}:
            return False
        return (
            self._http_request(pair[1], client)
            and _inert(body[1].value)
            and _contains(body[1].value, pair[0])
        )


def _module_name(relative: str) -> str:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".py":
        return ""
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if all(part.isidentifier() for part in parts) else ""


def _absolute_module(module: str, consumer_rel: str) -> str:
    if not module.startswith("."):
        return module
    level = len(module) - len(module.lstrip("."))
    package = _module_name(consumer_rel).split(".")
    if not consumer_rel.endswith("/__init__.py"):
        package = package[:-1]
    if level > len(package):
        return ""
    return ".".join([*package[: len(package) - level + 1], module[level:]]).rstrip(".")


class PythonDispatches:
    """Project-scoped source inventory; collisions cannot provide dispatch proof."""

    def __init__(self) -> None:
        self._sources: dict[tuple[str, str], str | None] = {}
        self._limited: set[tuple[str, str]] = set()
        self._modules: dict[tuple[str, str], _Module | None] = {}
        self._local_roots: dict[str, set[str]] = {}
        self._package_paths: set[tuple[str, str]] = set()
        self._file_paths: set[tuple[str, str]] = set()
        self._bytes = 0
        self._files = 0
        self._node_count = 0

    def note_path(self, project: str, relative: str) -> None:
        """Include unread files/directories when detecting import shadowing."""
        try:
            path = project_path(project, relative)
        except ValueError:
            return
        if path.is_absolute() or ".." in path.parts or not path.parts:
            return
        root = path.parts[0] if len(path.parts) > 1 else path.stem
        self._local_roots.setdefault(str(project), set()).add(root)
        for length in range(1, len(path.parts)):
            self._package_paths.add((str(project), ".".join(path.parts[:length])))
        if path.suffix == ".py" and path.name != "__init__.py":
            self._file_paths.add((str(project), _module_name(path.as_posix())))

    def add(self, project: str, relative: str, text: str) -> None:
        self.note_path(project, relative)
        try:
            relative = project_path(project, relative).as_posix()
        except ValueError:
            return
        module = _module_name(relative)
        if not module:
            return
        key = (str(project), module)
        if key in self._sources:
            self._sources[key] = None
            self._modules[key] = None
            self._limited.discard(key)
            return
        self._sources[key] = None
        # Only possible helper sources occupy the bounded source inventory.
        if "def " not in text or not ("[" in text or "httpx" in text):
            return
        size = len(text.encode("utf-8", errors="replace"))
        if self._files >= MAX_FILES or size > MAX_SOURCE_BYTES or self._bytes + size > MAX_TOTAL_BYTES:
            self._limited.add(key)
            return
        self._files += 1
        self._bytes += size
        self._sources[key] = text

    def _load(self, key: tuple[str, str]) -> _Module | None:
        if key in self._limited:
            raise DispatchLimitError("Python dispatch source inventory budget exceeded")
        if key in self._modules:
            return self._modules[key]
        text = self._sources.get(key)
        if text is None:
            return None
        try:
            tree = ast.parse(text)
            count = sum(1 for _ in _nodes(tree))
            if self._node_count + count > MAX_TOTAL_NODES:
                raise DispatchLimitError("Python dispatch total AST budget exceeded")
            self._node_count += count
            module = _Module(tree, self._local_roots.setdefault(key[0], set()))
        except (SyntaxError, ValueError) as error:
            if isinstance(error, DispatchLimitError):
                self._limited.add(key)
                raise
            self._modules[key] = None
            return None
        except (RecursionError, MemoryError) as error:
            self._limited.add(key)
            raise DispatchLimitError("Python dispatch parser budget exceeded") from error
        self._modules[key] = module
        return module

    def resolver(self, project: str, consumer_rel: str = "") -> Callable[[str, str], bool | None]:
        try:
            consumer_rel = project_path(project, consumer_rel).as_posix()
        except ValueError:
            consumer_rel = ""

        def resolve(module: str, symbol: str) -> bool | None:
            """``True`` proven, ``False`` a local source that proves nothing, ``None`` not local.

            ``None`` leaves the verdict to the caller's policy for modules whose
            source the scan cannot read; ``False`` is a veto: the local source
            was read and does not prove dispatch.
            """
            key = (str(project), _absolute_module(module, consumer_rel))
            if key in self._package_paths and key in self._file_paths:
                return False
            if key not in self._sources and key not in self._limited and key not in self._file_paths:
                return None
            parsed = self._load(key)
            try:
                return parsed is not None and parsed.dispatches(symbol)
            except (RecursionError, MemoryError) as error:
                self._limited.add(key)
                raise DispatchLimitError("Python dispatch analysis budget exceeded") from error

        return resolve


def has_dispatch_import(text: str, is_local: Callable[[str], bool]) -> bool:
    """Cheap conservative prefilter; the consumer AST must prove the actual import.

    This pass must not parse ordinary, unrelated source against a helper budget.
    Relative imports are deferred without using an absolute-module predicate.
    """
    for match in _FROM_IMPORT.finditer(text):
        module = match.group(1)
        if module.startswith("."):
            return True
        if all(part.isidentifier() for part in module.split(".")) and is_local(module):
            return True
    return False
