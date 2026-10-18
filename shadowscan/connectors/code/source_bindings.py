"""Import provenance values and bounded Python SDK-client parameter forwarding.

A matching annotation is not provenance. A second binding pass may use a typed
client only when visible, unambiguous call sites supply an import-bound SDK
construction. The main source visitor owns lexical scope and reachability and
supplies its resolver; this tracker never imports or evaluates scanned code.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceBinding:
    """The imported symbol behind a source name, possibly constructed already."""

    module: str
    symbol: str
    constructed: bool = False


@dataclass(frozen=True)
class SourceCall:
    binding: SourceBinding
    arguments: str
    line: int
    structural_arguments: str = ""
    node: ast.Call | None = None
    tool_factories: tuple[str, ...] = ()
    start: int = 0
    end: int = 0
    decorator: bool = False
    receiver: str = ""
    genkit_tools: tuple[str, ...] = ()
    # The argument text stops at MAX_CALL_TEXT (or the end of the source) before the
    # call closes: options past that point are unread, so they establish nothing.
    partial: bool = False


class PythonClientParameters:
    """Track a bounded single hop from SDK construction to a typed parameter."""

    def __init__(self, bindings: Mapping[str, Mapping[str, SourceBinding | None]] | None = None):
        # One bounded call-site pass supplies constructed SDK arguments to a
        # second binding pass. An annotation alone never proves an SDK client.
        self.parameter_bindings = bindings or {}
        self.parameter_calls: dict[str, dict[str, SourceBinding | None]] = {}
        self._parameter_functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._defined_parameter_functions: set[str] = set()

    def note_module(self, node: ast.Module, sites: Mapping[str, list[tuple[int, int]]], star: bool) -> None:
        self._parameter_functions = {
            item.name: item
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not item.decorator_list
            and sites.get(item.name) == [(item.lineno, item.col_offset)]
            and not star
            and len(item.args.posonlyargs) + len(item.args.args) + len(item.args.kwonlyargs) <= 32
        }

    def record_call(self, node: ast.Call, resolve: Callable[[ast.AST], SourceBinding | None]) -> None:
        """Join arguments to a unique module function; unknown calls destroy proof."""
        if not isinstance(node.func, ast.Name):
            return
        function = self._parameter_functions.get(node.func.id)
        if function is None or function.name not in self._defined_parameter_functions:
            return
        positional = [*function.args.posonlyargs, *function.args.args]
        arguments = self._parameter_arguments(function.args, node)
        candidates = {
            arg.arg: resolve(arguments[arg.arg]) if arg.arg in arguments else None
            for arg in [*positional, *function.args.kwonlyargs]
            if arg.annotation is not None
        }
        prior = self.parameter_calls.get(function.name)
        self.parameter_calls[function.name] = {
            name: value if prior is None or prior.get(name) == value else None
            for name, value in candidates.items()
        }

    @staticmethod
    def _parameter_arguments(parameters: ast.arguments, call: ast.Call) -> dict[str, ast.expr]:
        """Bind ordinary explicit calls only; invalid or variadic calls prove nothing."""
        positional = [*parameters.posonlyargs, *parameters.args]
        if len(call.args) > len(positional) or any(isinstance(arg, ast.Starred) for arg in call.args):
            return {}
        arguments = {arg.arg: value for arg, value in zip(positional, call.args, strict=False)}
        keyword_names = {arg.arg for arg in [*parameters.args, *parameters.kwonlyargs]}
        for keyword in call.keywords:
            if keyword.arg not in keyword_names or keyword.arg in arguments:
                return {}
            assert keyword.arg is not None
            arguments[keyword.arg] = keyword.value
        required = {arg.arg for arg in positional[: len(positional) - len(parameters.defaults)]}
        required.update(
            arg.arg
            for arg, default in zip(parameters.kwonlyargs, parameters.kw_defaults, strict=True)
            if default is None
        )
        return arguments if required <= arguments.keys() else {}

    def bind_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        resolve: Callable[[ast.AST], SourceBinding | None],
    ) -> dict[str, SourceBinding]:
        """Match a constructed call-site client to an import-bound annotation."""
        if isinstance(node, ast.Lambda):
            return {}
        if self._parameter_functions.get(node.name) is node:
            self._defined_parameter_functions.add(node.name)
        supplied = self.parameter_bindings.get(node.name, {})
        result: dict[str, SourceBinding] = {}
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            actual = supplied.get(arg.arg)
            annotation = resolve(arg.annotation) if arg.annotation is not None else None
            if (
                actual is not None
                and actual.constructed
                and annotation is not None
                and not annotation.constructed
                and annotation.module == actual.module == "openai"
                and annotation.symbol == actual.symbol
                and actual.symbol in {"OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI"}
            ):
                result[arg.arg] = actual
        return result

    def requires_second_pass(self) -> bool:
        return any(
            binding is not None and binding.constructed and binding.module == "openai"
            for args in self.parameter_calls.values()
            for binding in args.values()
        )
