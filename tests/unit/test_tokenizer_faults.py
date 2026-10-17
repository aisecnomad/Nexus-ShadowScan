"""A fault of CPython's tokenizer is read as a tokenizer error, wherever the scanner tokenizes Python.

CPython 3.12's tokenizer fails on a NUL byte after an indented line with an exception that says nothing
about the text, a SystemError or an AttributeError depending on the process (see
shadowscan.utils.python_tokens); the coverage-guided fuzz targets in tools/fuzz found it through the source
lexer and the redactor. Those, and the re-export prefilter, answer a source the tokenizer cannot read with
their fail-closed result instead of an exception: the lexer masks the rest and reports itself incomplete
(see test_source_ranges_python.py), the redactor withholds the rest of the text, and the prefilter says
the module is no import-only shim. Each fault is simulated, so every interpreter runs the path; the real
inputs run too, and on 3.12 they are what raised.
"""

from __future__ import annotations

import tokenize
from collections.abc import Callable, Iterator

import pytest

from shadowscan.connectors.code.python_reexports import _may_be_import_only
from shadowscan.utils import redaction_statements
from shadowscan.utils.redaction import SanitizationLimitError, sanitize_text

SECRET = "hunter2" + "-synthetic"
FAULTS: list[Exception] = [
    SystemError("<built-in method __new__ of type object> returned a result with an exception set"),
    AttributeError("type object 'TokenInfo' has no attribute '_make'"),
    KeyError("name"),
]


def fault_the_tokenizer(monkeypatch: pytest.MonkeyPatch, fault: Exception) -> None:
    def generate_tokens(readline: Callable[[], str]) -> Iterator[tokenize.TokenInfo]:
        raise fault
        yield  # pragma: no cover - makes this a generator, as the real one is

    monkeypatch.setattr(tokenize, "generate_tokens", generate_tokens)


@pytest.mark.parametrize("fault", FAULTS, ids=lambda fault: type(fault).__name__)
def test_the_redactor_withholds_the_rest_of_the_text_when_the_tokenizer_faults(
    monkeypatch: pytest.MonkeyPatch, fault: Exception
) -> None:
    fault_the_tokenizer(monkeypatch, fault)
    cleaned = sanitize_text(f'password = "{SECRET}"\nnext = 1\n')
    assert SECRET not in cleaned


@pytest.mark.parametrize("fault", FAULTS, ids=lambda fault: type(fault).__name__)
def test_the_reexport_prefilter_calls_a_module_the_tokenizer_cannot_read_no_shim(
    monkeypatch: pytest.MonkeyPatch, fault: Exception
) -> None:
    fault_the_tokenizer(monkeypatch, fault)
    assert _may_be_import_only("from .core import run\n") is False


def test_the_redactors_work_budget_still_ends_the_call_when_the_tokenizer_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The budget is charged by the readline the tokenizer calls. Its error must reach the caller, as the
    # documented failure of sanitize_text, and not be taken for a fault of the tokenizer and answered
    # with a result: the guard hands on what readline raised.
    monkeypatch.setattr(redaction_statements, "_MAX_REDACTION_WORK", 1)
    with pytest.raises(SanitizationLimitError):
        sanitize_text(f'password = "{SECRET}"\nnext = 1\n')


def test_the_redactor_reads_the_input_that_faults_cpython_3_12() -> None:
    cleaned = sanitize_text('passwd= ""\n-\x00')
    assert isinstance(cleaned, str)


def test_the_reexport_prefilter_reads_the_input_that_faults_cpython_3_12() -> None:
    assert _may_be_import_only("\tfrom .core import run\n\x00") is False
