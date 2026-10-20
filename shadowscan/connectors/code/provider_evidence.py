"""Provider helper provenance and tool-dispatch evidence assembly.

This pass consumes import-bound SDK objects and AST call identities from the
source binder. It never imports or executes scanned source. Type-only imports
keep the provider pass independent of the binder's runtime module.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from shadowscan.connectors.code.javascript_dispatch import javascript_responses_dispatch_lines
from shadowscan.connectors.code.provider_loops import provider_tool_loop_lines
from shadowscan.connectors.code.provider_tools import provider_tools_disabled
from shadowscan.connectors.code.responses_loops import responses_dispatch_lines, responses_tool_loop_lines
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal, Signature

if TYPE_CHECKING:
    from shadowscan.connectors.code.source_semantics import _Binding, _Call

_BUDGET_CHECK_NODES = 256

# Import-bound request calls whose response shape the loop recognizer understands.
_LOOP_REQUESTS: dict[str, tuple[str, frozenset[str]]] = {
    # Plain, raw-response (``.parse()`` returns the message) and streaming
    # (``get_final_message()`` / ``get_final_completion()``) request forms.
    "openai": (
        "provider.openai",
        frozenset(
            {
                f"{client}.{api}chat.completions.{method}"
                for client in ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI")
                for api in ("", "beta.")
                for method in ("create", "with_raw_response.create", "stream")
            }
        ),
    ),
    "anthropic": (
        "provider.anthropic",
        frozenset(
            {
                f"{client}.{api}messages.{method}"
                for client in (
                    "Anthropic",
                    "AsyncAnthropic",
                    "AnthropicBedrock",
                    "AsyncAnthropicBedrock",
                    "AnthropicVertex",
                    "AsyncAnthropicVertex",
                )
                for api in ("", "beta.")
                for method in ("create", "with_raw_response.create", "stream")
            }
        ),
    ),
}

# Signatures whose import-bound requests reach provider_tool_loop_lines, the
# only reader of cross-file dispatch resolution for a nested Python consumer.
LOOP_REQUEST_SIGNATURES = frozenset(signature for signature, _ in _LOOP_REQUESTS.values())

_JAVASCRIPT_OPENAI_CONSTRUCTORS = frozenset(
    {
        "default",
        "OpenAI",
        "AsyncOpenAI",
        "AzureOpenAI",
        "AsyncAzureOpenAI",
    }
)

_RESPONSES_CREATE = frozenset(
    {
        "OpenAI.responses.create",
        "AsyncOpenAI.responses.create",
        "AzureOpenAI.responses.create",
        "AsyncAzureOpenAI.responses.create",
    }
)


class ProviderHelperBindings:
    """Infer SDK parameters only from closed, agreeing direct helper calls."""

    def __init__(self, check_budget: Callable[[], float]):
        self.check_budget = check_budget
        self._helper_candidates: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._helper_references: dict[str, set[int]] = {}
        self._helper_arguments: dict[str, dict[int, dict[str, _Binding | None] | None]] = {}
        self._helper_annotations: dict[int, dict[str, _Binding]] = {}

    def collect(self, tree: ast.Module, sites: dict[str, list[tuple[int, int]]]) -> None:
        """Keep uniquely bound module functions used only by direct calls.

        An escaped helper could receive values at unseen call sites. Name
        collisions anywhere in the file, including another function's locals,
        deliberately forfeit this narrow interprocedural proof.
        """
        candidates = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and len(sites.get(node.name, ())) == 1
            and not node.decorator_list
            and node.args.vararg is None
            and node.args.kwarg is None
            and any(
                argument.annotation is not None
                for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            )
        }
        if not candidates:
            return
        direct: dict[int, ast.Call] = {}
        loads: dict[str, set[int]] = {}
        for number, node in enumerate(ast.walk(tree)):
            if not number % _BUDGET_CHECK_NODES:
                self.check_budget()
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                # Calls into namespace mutators are not simulated. A closed
                # helper proof stays within ordinary local assignments.
                return
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in candidates:
                direct[id(node.func)] = node
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in candidates:
                loads.setdefault(node.id, set()).add(id(node))
        for name, function in candidates.items():
            references = loads.get(name, set())
            if references and all(reference in direct for reference in references):
                self._helper_candidates[name] = function
                self._helper_references[name] = {id(direct[reference]) for reference in references}

    def record_call(self, call: ast.Call, resolve: Callable[[ast.AST], _Binding | None]) -> None:
        if not isinstance(call.func, ast.Name) or call.func.id not in self._helper_candidates:
            return
        function = self._helper_candidates[call.func.id]
        if id(function) not in self._helper_annotations:
            self._helper_arguments.setdefault(function.name, {})[id(call)] = None
            return  # the definition has not established this helper yet
        positional = [argument.arg for argument in (*function.args.posonlyargs, *function.args.args)]
        keyword_only = {argument.arg for argument in function.args.kwonlyargs}
        supplied: dict[str, ast.expr] = {}
        invalid = len(call.args) > len(positional) or any(isinstance(arg, ast.Starred) for arg in call.args)
        if not invalid:
            supplied.update(zip(positional, call.args, strict=False))
            for keyword in call.keywords:
                if (
                    keyword.arg is None
                    or keyword.arg in supplied
                    or keyword.arg not in {*positional[len(function.args.posonlyargs) :], *keyword_only}
                ):
                    invalid = True
                    break
                supplied[keyword.arg] = keyword.value
        required = positional[: len(positional) - len(function.args.defaults)]
        required.extend(
            argument.arg
            for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True)
            if default is None
        )
        invalid = invalid or any(name not in supplied for name in required)
        arguments = None if invalid else {name: resolve(value) for name, value in supplied.items()}
        self._helper_arguments.setdefault(function.name, {})[id(call)] = arguments

    def inferred_parameters(self) -> dict[int, dict[str, _Binding]]:
        """SDK parameters supported by actual, agreeing constructed arguments."""
        inferred: dict[int, dict[str, _Binding]] = {}
        for name, function in self._helper_candidates.items():
            observations = self._helper_arguments.get(name, {})
            if observations.keys() != self._helper_references[name] or any(
                arguments is None for arguments in observations.values()
            ):
                continue
            for parameter, expected in self._helper_annotations.get(id(function), {}).items():
                constructed = replace(expected, constructed=True)
                if all(
                    arguments is not None and arguments.get(parameter) == constructed
                    for arguments in observations.values()
                ):
                    inferred.setdefault(id(function), {})[parameter] = constructed
        return inferred

    def record_annotations(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, resolve: Callable[[ast.AST], _Binding | None]
    ) -> None:
        if self._helper_candidates.get(node.name) is not node:
            return
        annotations = {}
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            binding = resolve(argument.annotation) if argument.annotation is not None else None
            if (
                binding is not None
                and not binding.constructed
                and binding.module in _LOOP_REQUESTS
                and binding.symbol
                in {request.split(".", 1)[0] for request in _LOOP_REQUESTS[binding.module][1]}
            ):
                annotations[argument.arg] = binding
        self._helper_annotations[id(node)] = annotations


@dataclass
class _LoopRequests:
    """Import-bound request calls that the tool loop and dispatch recognizers follow."""

    provider: set[int] = field(default_factory=set)
    responses: set[int] = field(default_factory=set)
    javascript_constructors: set[int] = field(default_factory=set)

    def record(self, language: str, call: _Call, signatures: dict[str, Signature], parsed: bool) -> None:
        """Remember ``call`` if a recognizer follows it; ``parsed`` says a Python tree exists."""
        if (
            language == "javascript"
            and "provider.openai" in signatures
            and call.binding.module == "openai"
            and call.binding.symbol in _JAVASCRIPT_OPENAI_CONSTRUCTORS
        ):
            self.javascript_constructors.add(call.line)
        if not parsed or call.node is None:
            return
        if provider_tools_disabled(call.node):
            return
        loop_request = _LOOP_REQUESTS.get(call.binding.module)
        if (
            loop_request is not None
            and loop_request[0] in signatures
            and call.binding.symbol in loop_request[1]
        ):
            self.provider.add(id(call.node))
        if (
            "provider.openai" in signatures
            and call.binding.module == "openai"
            and call.binding.symbol in _RESPONSES_CREATE
        ):
            self.responses.add(id(call.node))


def protocol_evidence(
    index: SignatureIndex,
    tree: ast.AST | None,
    text: str,
    ignored: list[tuple[int, int]],
    requests: _LoopRequests,
    dispatch_calls: set[int],
    resolve_dispatch: Callable[[str, str], bool | None] | None = None,
) -> list[Match]:
    """Return tool-calling protocol evidence from the loops and dispatch around bound requests."""
    protocol = index.get("protocol.openai-function-calling")
    if protocol is None:
        return []
    found: list[Match] = []
    if tree is not None:
        # Autonomy: approval-bypass evidence. The loop runs each tool the model selects and feeds
        # the result back without a person approving the call.
        for line in provider_tool_loop_lines(
            tree, requests.provider, dispatch_calls=dispatch_calls, resolve_dispatch=resolve_dispatch
        ):
            found.append(
                Match(
                    protocol,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        capabilities=["tool-use", "autonomous"],
                        description="import-bound model-selected tool dispatch with conversation feedback",
                    ),
                    "provider tool-selection/dispatch/feedback loop",
                    0.9,
                    line=line,
                    extra={"verified_agent": True},
                )
            )
        for line in responses_tool_loop_lines(tree, requests.responses, dispatch_calls=dispatch_calls):
            found.append(
                Match(
                    protocol,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        capabilities=["tool-use", "autonomous"],
                        description="import-bound Responses function dispatch with ordered "
                        "conversation feedback",
                    ),
                    "OpenAI Responses tool-selection/dispatch/feedback loop",
                    0.9,
                    line=line,
                    extra={"verified_agent": True},
                )
            )
    dispatch_lines = (
        responses_dispatch_lines(tree, requests.responses, dispatch_calls=dispatch_calls)
        if tree is not None
        else javascript_responses_dispatch_lines(text, ignored, requests.javascript_constructors)
    )
    for line in dispatch_lines:
        found.append(
            Match(
                protocol,
                Signal(
                    type="code",
                    weight=0.85,
                    agent_indicator=True,
                    capabilities=["tool-use"],
                    description="import-bound Responses selected-action dispatch",
                ),
                "OpenAI Responses selected-action dispatch",
                0.85,
                line=line,
                extra={"verified_agent": True, "agent_classification": "openai-responses-tool-dispatch"},
            )
        )
    return found
