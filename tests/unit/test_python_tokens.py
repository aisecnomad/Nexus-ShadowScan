"""The guarded tokenizer separates the interpreter's own faults from errors in the source text.

CPython 3.12's C tokenizer can fail on a NUL byte after an indented line with an exception that says
nothing about the text, a SystemError or, when a type lookup is the first to notice, an AttributeError
(python/cpython#140576). Whichever interpreter runs these tests, the fault is simulated, and the real
inputs that cause it run too: they may tokenize, raise TokenError or raise TokenizerFault, nothing else.
"""

from __future__ import annotations

import io
import tokenize
from collections.abc import Callable, Iterator

import pytest

from shadowscan.utils.python_tokens import TokenizerFault, generate_tokens

SOURCE = "import os\nif os:\n    value = 'text'  # note\n"
SECRET = "hunter2" + "-synthetic"
FAULTS: list[Exception] = [
    SystemError("<built-in method __new__ of type object> returned a result with an exception set"),
    AttributeError("type object 'TokenInfo' has no attribute '_make'"),
    KeyError("name"),
    TypeError("argument"),
    RuntimeError("state"),
]

# Inputs on which CPython 3.12's tokenizer fails; 3.11 reads them and 3.13 raises TokenError.
NUL_INPUTS = [
    '\t""\n\x00',
    "\t1\n\x00",
    "\tif x\n\x00",
    "x = 1\n\x00y = 2\n",
    "a = (\n\x00",
    "\tx\n\x00\n\x00",
]


def tokens_of(text: str) -> list[tokenize.TokenInfo]:
    return list(generate_tokens(io.StringIO(text).readline))


def faulting_after(
    count: int, fault: BaseException
) -> Callable[[Callable[[], str]], Iterator[tokenize.TokenInfo]]:
    """A tokenizer that reads ``count`` tokens as the real one does and then raises ``fault``."""
    real = tokenize.generate_tokens

    def generate(readline: Callable[[], str]) -> Iterator[tokenize.TokenInfo]:
        for index, item in enumerate(real(readline)):
            if index == count:
                raise fault
            yield item
        raise fault

    return generate


def test_ordinary_source_gives_the_standard_libraries_tokens() -> None:
    assert tokens_of(SOURCE) == list(tokenize.generate_tokens(io.StringIO(SOURCE).readline))


def test_tokens_arrive_one_at_a_time_so_a_caller_can_stop_early() -> None:
    reads = 0

    def readline() -> str:
        nonlocal reads
        reads += 1
        return "x = 1\n" if reads < 1000 else ""

    stream = generate_tokens(readline)
    assert next(stream).string == "x"
    assert reads < 10


@pytest.mark.parametrize(
    ("source", "error"),
    [('"""never closed', tokenize.TokenError), ("if x:\n        a\n    b\n", IndentationError)],
)
def test_the_errors_the_tokenizer_documents_pass_through(source: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        tokens_of(source)


@pytest.mark.parametrize("fault", FAULTS, ids=lambda fault: type(fault).__name__)
@pytest.mark.parametrize("count", [0, 3])
def test_any_other_failure_of_the_tokenizer_is_a_fault(
    monkeypatch: pytest.MonkeyPatch, fault: Exception, count: int
) -> None:
    monkeypatch.setattr(tokenize, "generate_tokens", faulting_after(count, fault))
    seen: list[tokenize.TokenInfo] = []
    with pytest.raises(TokenizerFault):
        for item in generate_tokens(io.StringIO(SOURCE).readline):
            seen.append(item)
    assert len(seen) == count


def test_a_fault_names_the_exception_type_and_never_its_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tokenize, "generate_tokens", faulting_after(0, SystemError(f"quotes {SECRET}")))
    with pytest.raises(TokenizerFault) as caught:
        tokens_of(SOURCE)
    assert str(caught.value) == "SystemError"
    assert SECRET not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


class Budget(Exception):
    """Stands for a work budget the caller's readline enforces."""


def test_an_exception_from_the_callers_readline_is_not_a_fault() -> None:
    def readline() -> str:
        raise Budget("work limit")

    with pytest.raises(Budget):
        tokens_of_readline(readline)


def tokens_of_readline(readline: Callable[[], str]) -> list[tokenize.TokenInfo]:
    return list(generate_tokens(readline))


@pytest.mark.parametrize(
    "replacement", [AttributeError("replaced"), SyntaxError("replaced"), SystemError("x")]
)
def test_an_exception_from_readline_stays_the_callers_whatever_the_interpreter_makes_of_it(
    monkeypatch: pytest.MonkeyPatch, replacement: Exception
) -> None:
    # Were the tokenizer to replace an exception from readline with one of its own, the budget that
    # raised it must still reach the caller: the guard knows readline raised and hands that on.
    def generate(readline: Callable[[], str]) -> Iterator[tokenize.TokenInfo]:
        try:
            readline()
        except Budget:
            raise replacement from None
        yield from ()

    monkeypatch.setattr(tokenize, "generate_tokens", generate)

    def readline() -> str:
        raise Budget("work limit")

    with pytest.raises(Budget):
        tokens_of_readline(readline)


def test_a_readline_that_ends_the_input_with_stop_iteration_is_no_error() -> None:
    lines = iter(["x = 1\n"])

    def readline() -> str:
        return next(lines)  # raises StopIteration at the end, which the tokenizer reads as end of input

    assert [item.string for item in tokens_of_readline(readline)][:3] == ["x", "=", "1"]


def test_a_stop_iteration_from_readline_does_not_disguise_a_later_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = iter(["x = 1\n"])

    def readline() -> str:
        return next(lines)

    real = tokenize.generate_tokens

    def faulting_at_the_end(read: Callable[[], str]) -> Iterator[tokenize.TokenInfo]:
        yield from real(read)
        raise SystemError("late")

    monkeypatch.setattr(tokenize, "generate_tokens", faulting_at_the_end)
    with pytest.raises(TokenizerFault):
        tokens_of_readline(readline)


@pytest.mark.parametrize(
    "error", [MemoryError(), RecursionError(), UnicodeDecodeError("utf-8", b"", 0, 1, "x")]
)
def test_exhaustion_and_codec_errors_are_no_fault(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    monkeypatch.setattr(tokenize, "generate_tokens", faulting_after(0, error))
    with pytest.raises(type(error)):
        tokens_of(SOURCE)


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(1)])
def test_an_interrupt_is_never_taken_for_a_fault(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    monkeypatch.setattr(tokenize, "generate_tokens", faulting_after(0, error))
    with pytest.raises(type(error)):
        tokens_of(SOURCE)


@pytest.mark.parametrize("text", NUL_INPUTS, ids=lambda text: repr(text)[:24])
def test_nul_input_tokenizes_or_fails_in_a_way_callers_handle(text: str) -> None:
    try:
        tokens_of(text)
    except (tokenize.TokenError, SyntaxError, TokenizerFault):
        pass  # the three answers a caller handles; 3.12 gives the last, 3.13 the first
