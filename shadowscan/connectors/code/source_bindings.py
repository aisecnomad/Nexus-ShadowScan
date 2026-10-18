"""Import provenance values shared by the source binder and its collaborators.

A matching annotation is not provenance: client-through-parameter provenance is
established by the provider helper pass, which requires every visible call site
to supply the same import-bound SDK construction.
"""

from __future__ import annotations

import ast
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
    imported_tools: tuple[str, ...] = ()
    start: int = 0
    end: int = 0
    decorator: bool = False
    receiver: str = ""
    genkit_tools: tuple[str, ...] = ()
    # The argument text stops at MAX_CALL_TEXT (or the end of the source) before the
    # call closes: options past that point are unread, so they establish nothing.
    partial: bool = False
