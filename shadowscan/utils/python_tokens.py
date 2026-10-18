"""Python source tokens from the standard library, with the interpreter's own faults kept apart.

``tokenize.generate_tokens`` reports a source it cannot read with ``tokenize.TokenError``, the
``SyntaxError`` family and, for text that is not valid, ``UnicodeError``. CPython 3.12's C tokenizer can
also fail with an exception that says nothing about the text. For a NUL byte after an indented or
malformed line it hands back a token while an exception is still set (python/cpython#140576), and
whichever check runs first reports that exception: usually a ``SystemError`` ("returned a result with
an exception set") and, in some processes, an ``AttributeError`` for a name that exists, probably from
a type lookup that finds the pending exception. The type varies from process to process, so it cannot
be matched by name, and the same input is fine on 3.11 and an ordinary ``TokenError`` on 3.13. The 3.12
line receives security fixes only, and 3.12.13 still has the fault. The fuzz targets of #259
found it through the source lexer and the redactor.

:func:`generate_tokens` raises :class:`TokenizerFault` for any such failure, so a caller answers it the
way it answers a source the tokenizer rejects: with its fail-closed result, never with an exception that
reaches the scan. Only the tokenizer's own steps are guarded. An exception from ``readline`` (a work
budget, for example), the documented errors and resource exhaustion pass through unchanged, and the
caller's own loop body is never inside the guard.
"""

from __future__ import annotations

import tokenize
from collections.abc import Callable, Iterator

# What the tokenizer documents (TokenError, IndentationError and the rest of SyntaxError, codec errors,
# and the ValueError of a source it will not take) and what is no verdict on the text at all.
_PASSED_THROUGH = (tokenize.TokenError, SyntaxError, UnicodeError, ValueError, MemoryError, RecursionError)


class TokenizerFault(Exception):
    """The interpreter's tokenizer failed for a reason that is not an error in the source text."""


def generate_tokens(readline: Callable[[], str]) -> Iterator[tokenize.TokenInfo]:
    """``tokenize.generate_tokens(readline)``, raising :class:`TokenizerFault` for a fault of the tokenizer.

    The fault names only the type of the exception it replaces: its message can quote the source.
    """
    from_readline: list[BaseException] = []

    def guarded_readline() -> str:
        try:
            return readline()
        except StopIteration:
            raise  # the tokenizer reads it as the end of the input
        except BaseException as exc:
            # Noted to tell this exception from a fault of the tokenizer, and raised again unchanged.
            from_readline.append(exc)
            raise

    tokens = tokenize.generate_tokens(guarded_readline)
    while True:
        try:
            token = next(tokens)
        except StopIteration:
            return
        except Exception as exc:  # noqa: BLE001 - classified below; only documented errors pass as they are
            failure = exc
        else:
            yield token
            continue
        # What readline raised is the caller's own (a work budget, say) whatever the tokenizer made of
        # it. Of the rest, the tokenizer documents some errors; the type of a fault is no guide (see the
        # module docstring), so any other failure is one.
        if from_readline:
            raise from_readline[0]
        if isinstance(failure, _PASSED_THROUGH):
            raise failure
        raise TokenizerFault(type(failure).__name__) from None
