"""Fast lookup structures over the loaded signatures."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import threading
import time
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, fields
from functools import partial
from itertools import islice
from operator import itemgetter
from typing import Any, NamedTuple

import regex

from shadowscan.signatures.loader import Signal, Signature, load_signatures, normalise_package_name
from shadowscan.utils.redaction import sanitize_text
from shadowscan.utils.redaction_rules import environment_read_name, pasted_key_name

_SCAN_EXECUTION_CAP: ContextVar[float | None] = ContextVar("signature_scan_execution_cap", default=None)
REGEX_TIMEOUT_SECONDS = 0.1
# Per-execution allowance grows linearly with the input declared to
# scan_budget: a pattern may spend this long per million characters. The
# fail-fast property is size-relative, not absolute — a super-linear pattern
# still times out on large inputs, while a linear pattern with a large
# constant (keyword-dense megabyte files) is not misreported as pathological.
# Patterns must still pass the per-pattern throughput floor enforced by
# ``python -m shadowscan.signatures.validate``.
LINEAR_SECONDS_PER_MILLION_CHARS = 0.25
DEFAULT_SCAN_BUDGET_SECONDS = 2.0
# An input's budget is CPU time of the matching thread; a thread that merely
# waited for the scheduler has not spent it. Wall time still ends the input
# once it exceeds this multiple of the budget, so hostile input fails fast.
WALL_BUDGET_FACTOR = 4.0


class _ScanBudget:
    """The execution budget of one input: a CPU allowance and an absolute wall-clock cap."""

    __slots__ = (
        "cpu_deadline",
        "cpu_seconds",
        "cpu_started",
        "wall_deadline",
        "wall_seconds",
        "wall_started",
    )

    def __init__(self, cpu_seconds: float, wall_seconds: float, outer: _ScanBudget | None) -> None:
        self.cpu_seconds, self.wall_seconds = cpu_seconds, wall_seconds
        self.cpu_started, self.wall_started = time.thread_time(), time.monotonic()
        self.cpu_deadline = self.cpu_started + cpu_seconds
        self.wall_deadline = self.wall_started + wall_seconds
        if outer is not None:
            # A nested budget never outlives the one it runs under; the
            # diagnostic then describes the budget that actually ended it.
            if outer.cpu_deadline < self.cpu_deadline:
                self.cpu_deadline, self.cpu_seconds, self.cpu_started = (
                    outer.cpu_deadline,
                    outer.cpu_seconds,
                    outer.cpu_started,
                )
            if outer.wall_deadline < self.wall_deadline:
                self.wall_deadline, self.wall_seconds, self.wall_started = (
                    outer.wall_deadline,
                    outer.wall_seconds,
                    outer.wall_started,
                )

    def remaining(self) -> float:
        """Seconds left: the smaller of the CPU allowance and the wall cap."""
        return min(self.cpu_deadline - time.thread_time(), self.wall_deadline - time.monotonic())

    def exhausted(self) -> str:
        """Describe the spent budget for a diagnostic (static text, nothing from the input)."""
        cpu = time.thread_time() - self.cpu_started
        wall = time.monotonic() - self.wall_started
        return (
            f"signature matching exceeded the input execution budget (cpu {cpu:.2f}s of "
            f"{self.cpu_seconds:.2f}s, wall {wall:.2f}s of {self.wall_seconds:.2f}s)"
        )


_SCAN_BUDGET: ContextVar[_ScanBudget | None] = ContextVar("signature_scan_budget", default=None)
# A briefly busy worker can exhaust several regex wall-clock attempts before
# this thread has used its own 100 ms CPU allowance. Keep retries finite and
# inside the original per-pattern CPU and per-input wall deadlines.
_MAX_CONTENTION_RETRIES = 16


class MatchTimeoutError(RuntimeError):
    """Matching did not finish; callers must mark the input/scan incomplete."""


def _remaining_timeout() -> float:
    cap = _SCAN_EXECUTION_CAP.get() or REGEX_TIMEOUT_SECONDS
    budget = _SCAN_BUDGET.get()
    if budget is None:
        return cap
    remaining = budget.remaining()
    if remaining <= 0:
        raise MatchTimeoutError(budget.exhausted())
    return min(cap, remaining)


def pattern_timeout(default: float = REGEX_TIMEOUT_SECONDS) -> float:
    """Cap external pattern calls by the active per-input execution budget."""
    budget = _SCAN_BUDGET.get()
    if budget is None:
        return default
    remaining = budget.remaining()
    if remaining <= 0:
        raise MatchTimeoutError(budget.exhausted())
    return min(default, remaining)


def _run_regex(operation: Callable[[float], Any], context: str, *, max_seconds: float | None = None) -> Any:
    """Retry clear scheduler contention within the original execution budget.

    regex can charge CPU used by other threads while a scanner is suspended,
    including between iterator construction and its first next(). Only retry
    when this thread used less than half its original pattern budget. Manifest
    parsing can supply its separate per-pattern ceiling; every attempt remains
    subject to the same cumulative CPU and active per-input wall deadlines.
    Genuine expensive matching and repeated contention still fail closed.
    """

    def remaining_timeout() -> float:
        return _remaining_timeout() if max_seconds is None else pattern_timeout(max_seconds)

    budget = remaining_timeout()
    started = time.thread_time()
    for attempt in range(_MAX_CONTENTION_RETRIES + 1):
        elapsed = time.thread_time() - started
        remaining = min(remaining_timeout(), budget - elapsed)
        if remaining <= 0:
            raise MatchTimeoutError(f"signature matching timed out ({context}); input scan is incomplete")
        try:
            result = operation(remaining)
            remaining_timeout()
            if time.thread_time() - started >= budget:
                raise MatchTimeoutError(f"signature matching timed out ({context}); input scan is incomplete")
            return result
        except TimeoutError as exc:
            if attempt == _MAX_CONTENTION_RETRIES or time.thread_time() - started >= budget / 2:
                raise MatchTimeoutError(
                    f"signature matching timed out ({context}); input scan is incomplete"
                ) from exc


def _plan_candidates(
    plan: _RegexPlan, text: str, scan: LiteralScan | None
) -> tuple[set[int], dict[str, bool], str | None, dict[str, bool]]:
    """The plan entries whose first literal group occurs in ``text``, with the literal memos.

    Returns the candidates, the plain and casefolded presence memos and the
    casefolded text (None when no case-insensitive pattern needs it).
    """
    candidates = set(plan.unhinted)
    folded_text: str | None = None
    folded_present: dict[str, bool] = {}
    if scan is not None and scan.text is text:
        # A shared scan holds the union of the plans' literals; a plan's
        # candidates are the entries its own literals hit. The dicts also
        # memoise the remaining groups, so an absent literal is a False
        # entry, not a missing one.
        present = scan.present
        for literal in plan.plain_literals:
            if present.get(literal):
                candidates.update(plan.plain_first[literal])
        if plan.folded_literals:
            folded_text, folded_present = scan.folded_text, scan.folded_present
            for literal in plan.folded_literals:
                if folded_present.get(literal):
                    candidates.update(plan.folded_first[literal])
    else:
        present = {literal: True for literal in plan.plain_literals if literal in text}
        for literal in present:
            candidates.update(plan.plain_first[literal])
        if plan.folded_literals:
            folded_text = _fold(text)
            folded_present = {literal: True for literal in plan.folded_literals if literal in folded_text}
            for literal in folded_present:
                candidates.update(plan.folded_first[literal])
    return candidates, present, folded_text, folded_present


def _quota_matches(
    rx: Any,
    text: str,
    signature_id: str,
    quota: int,
    excluded: Callable[[int], bool] | None,
    limited: set[str] | None,
    selected: Callable[[Any], bool] | None = None,
) -> list[Any]:
    """At most ``quota`` selected matches of ``rx``; with ``limited``, one past it is looked for.

    A match past the quota is never returned. It records ``signature_id`` in
    ``limited``, so the caller can disclose that the matches are a lower bound.
    """
    if limited is None:
        return _finditer(rx, text, signature_id, quota, excluded, selected)
    found = _finditer(rx, text, signature_id, quota + 1, excluded, selected)
    if len(found) > quota:
        limited.add(signature_id)
        del found[quota:]
    return found


def _finditer(
    rx: Any,
    text: str,
    context: str,
    limit: int,
    excluded: Callable[[int], bool] | None = None,
    selected: Callable[[Any], bool] | None = None,
) -> list[Any]:
    if selected is not None:
        return _judged_finditer(rx, text, context, limit, excluded, selected)

    def collect(timeout: float) -> list[Any]:
        # Tiny patterns dominate this workload. Releasing/reacquiring the GIL
        # for every token under parallel connectors can spend the entire wall
        # deadline waiting for another thread. Engine timeouts remain preemptive
        # with concurrent=False and also bound any period holding the GIL.
        # The regex engine's iterator timeout also charges CPU work performed
        # between next() calls. Consume only the caller's remaining match quota
        # before redaction or other connector threads can process yielded hits.
        # Never materialize the unbounded sequence of matches in a large input.
        matches = rx.finditer(text, timeout=timeout, concurrent=False)
        if excluded is not None:
            matches = (match for match in matches if not excluded(match.start()))
        return list(islice(matches, limit))

    result: list[Any] = _run_regex(collect, context)
    return result


# The raw matches a judged pattern reads per regex execution (``_judged_finditer``).
_JUDGED_BATCH = 64


def _judged_finditer(
    rx: Any,
    text: str,
    context: str,
    limit: int,
    excluded: Callable[[int], bool] | None,
    selected: Callable[[Any], bool],
) -> list[Any]:
    """At most ``limit`` matches of ``rx`` that ``selected`` accepts, judged between regex executions.

    The regex engine's iterator timeout charges the CPU spent between two
    next() calls to the pattern. A judge run inside the iteration (the
    credential judge reads up to ``_FOLLOWER_CHARS`` after each match) spent
    the pattern's execution allowance, which scales with the input's size and
    not with its matches, so a file of a few thousand credential reads timed
    out (MatchTimeoutError, exit 3) where the pattern alone finishes in time.

    The matches are read in batches of ``_JUDGED_BATCH`` instead. Each
    execution resumes where the last batch ended and is given only what the
    earlier ones left of one execution allowance, so the engine's own work is
    held to the allowance an unjudged run has. The judge runs between the
    executions and is charged to the input's execution budget, which still
    ends the input, and marks it incomplete, when spent.
    """
    allowance = _remaining_timeout()
    spent = 0.0
    found: list[Any] = []
    position = 0
    while True:

        def batch(timeout: float, start: int = position) -> list[Any]:
            return list(islice(rx.finditer(text, start, timeout=timeout, concurrent=False), _JUDGED_BATCH))

        started = time.thread_time()
        matches: list[Any] = _run_regex(batch, context, max_seconds=allowance - spent)
        spent += time.thread_time() - started
        for match in matches:
            if (excluded is None or not excluded(match.start())) and selected(match):
                found.append(match)
                if len(found) >= limit:
                    return found
        _remaining_timeout()
        if len(matches) < _JUDGED_BATCH:
            return found
        # Secret patterns never match empty text; were one to, the next
        # execution must still move on.
        last = matches[-1]
        position = last.end() + (last.end() == last.start())


def _search(rx: Any, text: str, context: str) -> Any:
    return _run_regex(lambda timeout: rx.search(text, timeout=timeout, concurrent=False), context)


def _plain_search(rx: Any, text: str, context: str, timeout: float) -> Any:
    """Search one short host token with a timeout the caller checked once per token.

    Tokens are at most 253 characters and the domain patterns are anchored, so
    the engine's own preemption is the only bookkeeping most calls need. A
    wall-clock timeout can still come from a sibling thread's CPU charged to
    this one; the retrying path then decides whether it was contention.
    """
    try:
        return rx.search(text, timeout=timeout, concurrent=False)
    except TimeoutError:
        return _search(rx, text, context)


def _budgeted_search(rx: Any, text: str, context: str, timeout: float) -> Any:
    """Full per-call bookkeeping for hosts supplied by connectors rather than the tokenizer."""
    return _search(rx, text, context)


GENERIC_CREDENTIAL = "heuristic.inline-credential"
UNATTRIBUTED_KEY = "heuristic.unattributed-api-key"
# Credential matches kept per secret signal and text. A text with more
# credentials of one format than this is reported with the quota's worth of
# evidence and a disclosure that the count is a lower bound (``match_secrets``).
MAX_SECRETS_PER_SIGNAL = 5
# An unattributed sk- value shorter than this after the prefix must look random.
_SHORT_KEY_BODY = 32
_VALUE_END = frozenset("\"',;")


def _assigned_value(value: str) -> str:
    """The value of a ``NAME = value`` or ``NAME: value`` match, or the whole text when it is no assignment.

    Plain string scanning, so the cost stays linear in the match length.
    """
    positions = [i for i in (value.find("="), value.find(":")) if i >= 0]
    if not positions:
        return value
    rest = value[min(positions) + 1 :].lstrip(" \t").lstrip("\"'")
    for i, char in enumerate(rest):
        if char in _VALUE_END or char.isspace():
            return rest[:i]
    return rest


# A value that names something instead of holding it: a member chain
# ('process.env.OPENAI_API_KEY', 'self.cleaned_data', 'config.fireCrawlApiKey',
# 'hasher.encode') or a single identifier. The generic pattern's value class
# admits '.' and '_', so these passed as long, diverse credentials.
_IDENTIFIER_CHAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
# A lower-case letter followed by a capital: the word boundary of camelCase.
_CASE_BOUNDARY = re.compile(r"[a-z][A-Z]")
# The words of a name: 'fireCrawlApiKey' is fire, Crawl, Api, Key; 'ANTHROPIC_API_KEY'
# is ANTHROPIC, API, KEY.
_NAME_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
# Three or more letter words joined by '-' or '_': a label or a test value
# ('request-scoped-credential', 'fc-shared-env-must-not-be-used'), or a
# generated passphrase ('snout-fiber-thump-bloom-gravel'); see _label_slug.
_WORD_SLUG = re.compile(r"[A-Za-z]{2,}(?:[-_][A-Za-z]{2,}){2,}")
# Password managers also join words with '.', but a dotted string of words in
# source code or configuration names something: a package or an Android key
# ('net.openid.appauth.state', 'com.google.android.geo'), an i18n message
# ('forms.login.field.hint'), a namespace ('Microsoft.Identity.Client') or a
# member chain ('config.openai.apiKey'). Only where a value can name nothing,
# a password in an env or credential file, is a dotted slug whose words are
# each lower case, Capitalized or upper case a passphrase
# ('snout.fiber.thump', 'Snout.Fiber.Thump'); see _high_entropy_credential.
_SLUG_WORD = r"(?:[a-z]{2,}|[A-Z][a-z]+|[A-Z]{2,})"
_DOTTED_SLUG = re.compile(_SLUG_WORD + r"(?:\." + _SLUG_WORD + r"){2,}")
_SLUG_SEPARATOR = re.compile(r"[-_.]")
# Words that make a word slug a label on their own, read with a plural '-s'
# or a past '-ed' taken off (``_label_strength``): credential, placeholder,
# development and filler words that passphrase word lists leave out
# ('request-scoped-credential', 'rotate-these-tokens', 'foo-bar-baz-qux-quux').
_LABEL_WORDS = frozenset(
    {
        # What the value stands for.
        "api",
        "auth",
        "credential",
        "env",
        "passwd",
        "password",
        "pwd",
        "secret",
        "token",
        # Test values and placeholders.
        "demo",
        "dummy",
        "example",
        "fake",
        "fixture",
        "mock",
        "placeholder",
        "sample",
        "stub",
        "testing",
        # Development defaults ('local-development-only', 'insecure-default-for-dev').
        "development",
        "insecure",
        "localhost",
        "production",
        # Filler text ('foo-bar-baz-qux-quux', 'lorem-ipsum-dolor-sit-amet').
        "baz",
        "foo",
        "foobar",
        "ipsum",
        "quux",
        "qux",
    }
)
# Label vocabulary that is also an ordinary word of a passphrase word list, as
# are its plural and past forms ('passed', 'valued', 'keyed', 'tested', 'devs',
# 'locals'): a slug is a label by these only with another label word or with a
# function word ('unsafe-dev-only-default', 'this-should-be-changed').
_COMMON_LABEL_WORDS = frozenset(
    {
        "change",
        "default",
        "dev",
        "invalid",
        "key",
        "local",
        "lorem",
        "pass",
        "prod",
        "replace",
        "scoped",
        "shared",
        "test",
        "unsafe",
        "value",
        "your",
    }
)
# Words that join a sentence, which generated passphrases leave out but labels
# written as instructions need ('dont-use-this-in-prod', 'for-local-dev-use-only').
_FUNCTION_WORDS = frozenset(
    {
        "and",
        "are",
        "be",
        "do",
        "does",
        "dont",
        "for",
        "from",
        "here",
        "in",
        "is",
        "it",
        "must",
        "never",
        "no",
        "not",
        "of",
        "on",
        "only",
        "or",
        "should",
        "the",
        "these",
        "this",
        "to",
        "use",
        "was",
        "were",
        "with",
    }
)


def _label_strength(word: str) -> int:
    """How a lower-case slug word marks a label, read with a plural or past ending taken off.

    2: label vocabulary on its own (``_LABEL_WORDS``); 1: vocabulary that is
    also a common word (``_COMMON_LABEL_WORDS``); 0: neither.
    """
    stems = {word, word[:-1] if word.endswith("s") else word}
    if word.endswith("ed"):
        stems.update((word[:-1], word[:-2]))  # 'changed' is change, 'tested' is test
    if not stems.isdisjoint(_LABEL_WORDS):
        return 2
    return int(not stems.isdisjoint(_COMMON_LABEL_WORDS))


def _label_word(word: str) -> bool:
    """Whether a lower-case word is label vocabulary of either kind (``_label_strength``)."""
    return _label_strength(word) > 0


_VALUE_QUOTES = "\"'"


def _assignment_parts(value: str) -> tuple[str, bool]:
    """The assigned value of a ``NAME = value`` match, and whether a quote opened it."""
    positions = [i for i in (value.find("="), value.find(":")) if i >= 0]
    if not positions:
        return value, False
    rest = value[min(positions) + 1 :].lstrip(" \t")
    return _assigned_value(value), rest[:1] in _VALUE_QUOTES


def _identifier_shaped(value: str) -> bool:
    """Whether ``value`` reads as a program name rather than random key material.

    Names are made of words: at least 60% of their letters fall in words of
    three letters or more ('os.environ', 'encode_md5_hash', 'SetUnusablePasswordMixin').
    Random keys split into one- and two-letter fragments ('eyJhbGciOiJIUzI1NiJ9':
    ey, Jhb, Gci, Oi, JI ...) and carry more digits.
    """
    letters = sum(char.isalpha() for char in value)
    if not letters or sum(char.isdigit() for char in value) * 3 > len(value):
        return False
    in_words = sum(len(word) for word in _NAME_WORD.findall(value) if word.isalpha() and len(word) >= 3)
    return in_words * 5 >= letters * 3


# What follows a member chain in code but never a literal in configuration: a
# call, a subscript, the end of a statement, the end of an argument or member.
_CODE_FOLLOWERS = frozenset("([;),}")
# Chains that are references wherever they are written.
_REFERENCE_ROOTS = ("process.env.", "import.meta.env.", "os.environ.", "self.", "this.")


def _reference_value(value: str, *, code: bool, follower: str = "") -> bool:
    """Whether a generic match assigns a reference to a credential rather than a literal.

    In source code (``code``) an unquoted value is an expression, so an
    identifier or a member chain names a variable ('self.api_key = api_key',
    'k = settings.OPENAI_API_KEY'). Elsewhere an unquoted value is a literal
    ('DB_PASSWORD=Summer.Vacation2024' in an env file), so only a member chain
    that code follows (``follower``, the text after the match, starts with '('
    after 'hasher.encode' or ';' after 'process.env.KEY' in a documentation
    snippet) or that starts from the environment or the instance is one. A
    quoted value is always a literal, and a random-looking value is never a
    name. Operands after a reference are read by ``_fallback_literal``. A
    match that assigns nothing (the bare ``AKIA...`` and ``ghp_...`` token
    patterns) is the token itself, never a name for one.
    """
    if "=" not in value and ":" not in value:
        return False
    candidate, quoted = _assignment_parts(value)
    if quoted or not _IDENTIFIER_CHAIN.fullmatch(candidate) or not _identifier_shaped(candidate):
        return False
    if code:
        return True
    return "." in candidate and (follower[:1] in _CODE_FOLLOWERS or candidate.startswith(_REFERENCE_ROOTS))


# How much of the text after a generic match is read for operands that follow it.
_FOLLOWER_CHARS = 512
# The text after a reference, read as tokens: each one is matched where the
# last one ended, so the read is linear in the follower. Blanks (any white
# space but a line end, such as U+00A0, U+2009, U+3000, '\f' and '\v', the
# zero-width space, word joiner and byte order mark that an editor or a paste
# leaves between tokens, and Python's backslash continuation), a line end, a
# comment, a string literal with its prefix ('f"..."', C#'s '$"..."') and
# Python's triple quotes on one line ('"""..."""'), a member access ('.trim',
# '?.trim', '?.' before a call), an operator, TypeScript's non-null '!', a
# word, a bracket, and any other single character.
_OPERAND_TOKEN = re.compile(
    r"(?P<blank>(?:[^\S\r\n]|[\u200b\u2060\ufeff]|\\(?:\r\n|\r|\n))++)"
    r"|(?P<newline>\r\n|\r|\n)"
    r"|(?P<comment>(?://|#)[^\r\n]*+|/\*(?:[^*]|\*(?!/))*+\*/)"
    r"|(?P<string>(?P<prefix>[rRbBuUfF]{1,2}|[@$])?(?P<quote>\"\"\"|'''|[\"'`])"
    r"(?P<body>(?:\\[^\r\n]|(?!(?P=quote))[^\\\r\n])*+)(?P=quote))"
    r"|(?P<member>\??\.[A-Za-z_$][\w$]*+|\?\.(?=[(\[]))"
    r"|(?P<operator>\|\||\?\?|\?:|&&|===?|!==?|[?:+])"
    r"|(?P<postfix>!)"
    r"|(?P<word>[A-Za-z_$][\w$]*+)"
    r"|(?P<open>[(\[{])|(?P<close>[)\]}])"
    r"|(?P<other>[\s\S])"
)
_CLOSERS = {"(": ")", "[": "]", "{": "}"}
# Operators whose next operand is the value when the reference is unset: a
# fallback ('||', '??', Kotlin's '?:', Python's 'or'), a ternary branch ('?',
# ':', Python's 'else') or a concatenation ('+').
_FALLBACK_OPERATORS = frozenset({"||", "??", "?:", "?", ":", "+", "or", "else"})
# Operators the value goes on past whose next operand is no fallback: a
# comparison, a conjunction, the condition of Python's 'a if c else b' and the
# type of a TypeScript cast ('process.env.X as string || "<key>"').
_OTHER_OPERATORS = frozenset({"&&", "==", "===", "!=", "!==", "and", "if", "as", "satisfies"})
# A fallback literal is one token of the generic value class, as an assigned
# value is: a sentence ('"OPENAI_API_KEY is not set"') is a message.
_FALLBACK_TOKEN = re.compile(r"[A-Za-z0-9_./+=-]{16,256}")
# What any such literal starts with: a quote and 16 characters of the class.
# A follower without one holds no fallback literal, and the operand reader,
# Python at several microseconds a token, is not run (``_fallback_literal``).
_FALLBACK_HINT = re.compile(r"[\"'`][A-Za-z0-9_./+=-]{16}")


class _OperandToken(NamedTuple):
    kind: str
    token: re.Match[str]
    # Whether blanks, a comment or a line end came before the token, how many
    # line ends, and whether a line between was empty: no token, no comment.
    spaced: bool
    lines: int
    gap: bool


def _operand_tokens(follower: str) -> Iterator[_OperandToken]:
    """The tokens of ``follower`` other than blanks, comments and line ends, which they annotate."""
    position = 0
    spaced, lines, gap = False, 0, False
    # Whether the current line holds a token or a comment; the follower's
    # first line is the match's own.
    filled = True
    while position < len(follower):
        token = _OPERAND_TOKEN.match(follower, position)
        if token is None:  # pragma: no cover - the last alternative matches any character
            return
        position = token.end()
        kind = token.lastgroup or "other"
        if kind == "blank":
            spaced = True
        elif kind == "comment":
            spaced = filled = True
        elif kind == "newline":
            spaced, lines, gap, filled = True, lines + 1, gap or not filled, False
        else:
            yield _OperandToken(kind, token, spaced, lines, gap)
            spaced, lines, gap, filled = False, 0, False, True


def _closed_group(tokens: Iterator[_OperandToken], opener: str) -> bool:
    """Read the tokens of a call, subscript or other bracketed group up to its closing bracket.

    False when the group does not close, or closes with the wrong bracket,
    within the follower.
    """
    expected = [_CLOSERS[opener]]
    for item in tokens:
        if item.kind == "open":
            expected.append(_CLOSERS[item.token.group()])
        elif item.kind == "close":
            if item.token.group() != expected.pop():
                return False
            if not expected:
                return True
    return False


# What a type argument list holds besides names, members ('System.String') and
# nested lists: separators, nullable and array marks, unions and intersections.
_TYPE_ARGUMENT_MARKS = frozenset({",", "?", "[", "]", "|", "&"})


def _type_arguments(tokens: Iterator[_OperandToken]) -> bool:
    """Read the type arguments of a generic call, after its '<', up to the matching '>'.

    'configService.get<string>("X") ?? "<key>"' (NestJS), C#'s
    'GetValue<string>("X")' and Kotlin's 'getProperty<String>("x")' read the
    same setting as the untyped call. False when anything but a type's names
    and marks comes first, or the list does not close within the follower.
    """
    depth = 1
    for item in tokens:
        text = item.token.group()
        if text in {"<", ">"}:
            depth += 1 if text == "<" else -1
            if not depth:
                return True
        elif item.kind not in {"word", "member"} and text not in _TYPE_ARGUMENT_MARKS:
            return False
    return False


def _operator(item: _OperandToken) -> str | None:
    """The operator a token is, or None: a symbol, or one of Python's word operators.

    Python's 'if' at the start of a line begins a statement, not the
    condition of a conditional expression.
    """
    text = item.token.group()
    if item.kind == "operator" or (item.kind == "word" and text in _FALLBACK_OPERATORS | _OTHER_OPERATORS):
        return None if text == "if" and item.lines else text
    return None


def _fallback_literal(value: str, follower: str) -> str | None:
    """The key-shaped literal that is a direct fallback operand after a reference, or None.

    The generic pattern's value stops at the first blank, so for
    'apiKey = process.env.OPENAI_API_KEY || "<key>"' it covers only the read.
    The value goes on only through operators (``_FALLBACK_OPERATORS`` and
    ``_OTHER_OPERATORS``) between operands: string literals, names and member
    chains ('?? process.env.B ?? "<key>"'), each with its calls, subscripts,
    generic type arguments (``_type_arguments``: 'get<string>("X") ??') and
    non-null or optional members ('GetEnvironmentVariable("X") ??',
    'process.env.X?.trim() ||', 'getKey()!.value ??') and a TypeScript cast
    ('as string ||'), and bracketed groups. Parentheses around an operand
    ('|| ("<key>")', '|| (a || "<key>")') are read through, so the operand
    inside is direct.
    An operator may end a line or start a later one, after comment lines or
    a backslash continuation; an empty line before an operator, a value end
    (';', ',', a closing bracket) or any other token ends the value. After an
    operator its operand must follow, so empty and comment lines may come
    between them ('||\n  // dev fallback\n  "<key>"'). A string literal right after
    a fallback operator is a hard-coded credential when it is one token of the
    value class (``_FALLBACK_TOKEN``) that looks like a key
    (``_high_entropy_credential``). A literal inside a call
    ('?? getSecret("<path>")', '?: error("X is not set")') is no fallback,
    nor is an empty, word-like or interpolated one ('|| ""', '|| f"{x}"').
    Whether the literal is a placeholder is the caller's test, on the literal
    itself (see ``reported_credential``). A follower without the start of
    such a literal anywhere (``_FALLBACK_HINT``) is not read at all.
    """
    if _FALLBACK_HINT.search(follower) is None:
        return None
    tokens = _operand_tokens(follower)
    operand = fallback = False
    # Parentheses opened where an operand belongs and not closed yet.
    grouping = 0
    for item in tokens:
        kind, token = item.kind, item.token
        if item.gap and not operand:
            return None
        if operand:
            if kind == "open" and token.group() == "(":
                grouping += 1  # '|| ("<key>")': the operand is inside
                continue
            if kind == "string" and fallback and _fallback_credential(value, token):
                return str(token["body"])
            if kind not in {"string", "word", "open"} or (
                kind == "open" and not _closed_group(tokens, token.group())
            ):
                return None
            operand = False
        elif kind == "close" and grouping and token.group() == ")":
            grouping -= 1
        elif kind == "member" or (not item.spaced and kind in {"open", "postfix"}):
            # A member, call, subscript or non-null assertion on the operand before.
            if kind == "open" and not _closed_group(tokens, token.group()):
                return None
        elif token.group() == "<" and not item.spaced:
            # A generic call's type arguments ('get<string>(...)', 'GetValue<string>(...)').
            if not _type_arguments(tokens):
                return None
        else:
            operator = _operator(item)
            if operator is None:
                return None
            operand, fallback = True, operator in _FALLBACK_OPERATORS
    return None


def _fallback_credential(value: str, token: re.Match[str]) -> bool:
    """Whether a string literal after a fallback operator is a key: one plain token that looks random.

    A token made of words and numbers is a mode, a label, a path or a name
    (``_worded_literal``), not a key, wherever it is a fallback.
    """
    body = token["body"]
    plain = not _interpolated_literal(token) and _FALLBACK_TOKEN.fullmatch(body) is not None
    return plain and not _worded_literal(body) and _high_entropy_credential(value, literal=body)


# The separators of a fallback literal's segments, and a segment that reads
# as a word or a number: a lower-case, Capitalized or upper-case word, digits,
# a word with a short version ('oauth2', 'v2') or three characters or fewer
# ('x', '4o', '07').
_LITERAL_SEPARATOR = re.compile(r"[-_./:]")
_WORDED_SEGMENT = re.compile(r"[a-z]+|[A-Z][a-z]*|[A-Z]+|[0-9]+|[A-Za-z]+[0-9]{1,2}|[A-Za-z0-9]{1,3}")


def _worded_literal(literal: str) -> bool:
    """Whether a literal is two or more segments that each read as a word or a number.

    A default mode or label ('anonymous-public-access',
    'disabled-in-this-build', 'managed-identity-fallback'), a header name
    ('x-api-key-header-name'), a URL path ('/oauth2/v2.0/authorize') and a
    model id ('gpt-4o-mini-2024-07-18') are; a key has a segment that mixes
    letters and digits at random ('3f9a8b7c-...', 'R4nd0m9Qx2Vb7Lp6'). A
    fallback is held to looking like a token, not like a passphrase: a word
    slug there reads as a setting's default.
    """
    segments = [segment for segment in _LITERAL_SEPARATOR.split(literal) if segment]
    return len(segments) >= 2 and all(_WORDED_SEGMENT.fullmatch(segment) for segment in segments)


def _interpolated_literal(token: re.Match[str]) -> bool:
    """Whether a string token assembles its text from expressions ('f"{x}"', '`${x}`', C#'s '$"..."')."""
    prefix, body = (token["prefix"] or "").lower(), token["body"]
    return prefix == "$" or ("f" in prefix and "{" in body) or (token["quote"] == "`" and "${" in body)


# Below this share of digits a separated single-case value reads as an identifier
# with a version or size in it, not as a hex or base-36 token such as ``dop_v1_<64 hex>``.
_IDENTIFIER_MAX_DIGIT_SHARE = 0.25
# A value without digits is kept only when its letters mix cases the way a random
# token does; camelCase keeps upper case rarer, CONSTANT_CASE has no lower case.
_RANDOM_UPPER_SHARE = (0.3, 0.7)


def _single_case_identifier(candidate: str) -> bool:
    """Whether an assigned value is the name of another variable rather than a literal token.

    A snake_case, CONSTANT_CASE or dotted attribute path:
    ``include_tracing_api_key``, ``ANTHROPIC_API_KEY``,
    ``settings.openai_api_key_v2``. The generic credential patterns accept an
    unquoted value because ``.env`` and shell assignments carry none, so
    ``api_key=resolved_api_key`` matches the same way ``api_key=9f86d0...``
    does. A name is told from a token by its shape: separated by ``_`` or
    ``.`` into identifier segments, its letters all one case, and few digits.
    A snake_case password with a year in it (``my_secret_password_2024``) is
    given up for that; the specific provider patterns do not pass through
    here.
    """
    if not _IDENTIFIER_CHAIN.fullmatch(candidate) or ("_" not in candidate and "." not in candidate):
        return False
    letters = [char for char in candidate if char.isalpha()]
    single_case = all(char.islower() for char in letters) or all(char.isupper() for char in letters)
    if not letters or not single_case:
        return False
    digits = sum(char.isdigit() for char in candidate)
    return digits / len(candidate) < _IDENTIFIER_MAX_DIGIT_SHARE


def _assigned_name(value: str) -> str:
    """The name of a ``NAME = value`` or ``NAME: value`` match, or '' when it is no assignment."""
    positions = [i for i in (value.find("="), value.find(":")) if i >= 0]
    return value[: min(positions)] if positions else ""


def _label_slug(value: str, candidate: str, *, names: bool = True) -> bool:
    """Whether a word slug assigned in ``value`` is a label rather than a generated passphrase.

    Password managers generate passphrases as random words joined by '-', '_'
    or '.' ('snout-fiber-thump-bloom-gravel', 'Ostrich-Lantern-Volcano-Tangerine',
    'snout.fiber.thump.bloom.gravel', 'SNOUT-FIBER-THUMP-BLOOM-GRAVEL'), which
    is also the shape of a label. A label says what it stands for: one of its
    words is credential, placeholder, development or filler vocabulary that
    word lists leave out ('request-scoped-credential',
    'fc-shared-env-must-not-be-used', 'local-development-only',
    'lorem-ipsum-dolor-sit-amet'), two are vocabulary that is also a common
    word ('unsafe-dev-only-default', 'defaults-were-replaced'), one such word
    comes with a function word that joins a sentence
    ('this-should-be-changed', 'dont-use-this-in-prod'), see
    ``_label_strength``, or a word has three letters or more of the name it
    is assigned to ('OPENAI_API_KEY=sua_chave_openai'; 'db' in 'DB_PASSWORD'
    is too short to tell). One common word alone does not make a label: a
    passphrase may hold 'passed', 'keyed', 'default' or 'lorem'. With
    ``names``, an upper-case slug joined by '_' only is CONSTANT_CASE, an
    environment variable's name.
    """
    if names and candidate.isupper() and "-" not in candidate and "." not in candidate:
        return True
    words = [word.lower() for word in _SLUG_SEPARATOR.split(candidate)]
    name = {word.lower() for word in _NAME_WORD.findall(_assigned_name(value)) if len(word) >= 3}
    if not name.isdisjoint(words):
        return True
    strengths = [_label_strength(word) for word in words]
    common = strengths.count(1)
    return 2 in strengths or common >= 2 or (common == 1 and not _FUNCTION_WORDS.isdisjoint(words))


def _name_shaped(candidate: str) -> bool:
    """Whether a value is built like a program name: snake_case, dotted, CONSTANT_CASE or camelCase.

    A single run of letters ('correcthorsebatterystaple', an AKIA key's
    digit-free body) is not: it carries no name structure to tell it from a
    token, so only the entropy tests judge it.
    """
    return _IDENTIFIER_CHAIN.fullmatch(candidate) is not None and (
        "_" in candidate or "." in candidate or _CASE_BOUNDARY.search(candidate) is not None
    )


def _program_name(candidate: str, body: str, *, passphrase: bool) -> bool:
    """Whether a value is built like another variable's name rather than a token (#258's shape rules).

    A name-shaped value with no digit (``_name_shaped``) that does not mix
    cases evenly is one, unless it is a passphrase of words; a value with
    digits is one when it is a single-case identifier
    (``_single_case_identifier``).
    """
    if any(char.isdigit() for char in body):
        return _single_case_identifier(candidate)
    letters = [char for char in body if char.isalpha()]
    if passphrase or not letters or not _name_shaped(candidate):
        return False
    upper_share = sum(char.isupper() for char in letters) / len(letters)
    low, high = _RANDOM_UPPER_SHARE
    return upper_share < low or upper_share > high


def _high_entropy_credential(value: str, *, literal: str | None = None, names: bool = True) -> bool:
    """Require a generic assigned credential to be long, diverse and shaped like a token, not a name.

    Shannon entropy alone does not separate the two: ordinary identifiers
    clear 3 bits per character. With ``names`` the value may be another
    variable's name, so one built like a name is none (``_program_name``),
    a CONSTANT_CASE word slug is a label (``_label_slug``) and a dotted
    string of words is a name (``_DOTTED_SLUG``). ``literal``
    is the value to judge when it is not the one ``value`` assigns (a
    fallback after a reference); ``value`` still names it.
    """
    candidate = _assigned_value(value) if literal is None else literal
    passphrase = _WORD_SLUG.fullmatch(candidate) is not None or (
        not names and _DOTTED_SLUG.fullmatch(candidate) is not None
    )
    if len(candidate) < 16 or (passphrase and _label_slug(value, candidate, names=names)):
        return False
    body = re.sub(r"[^A-Za-z0-9]", "", candidate)
    if len(body) < 2 or len(set(body)) <= 2:
        return False
    adjacent = sum(abs(ord(left) - ord(right)) <= 1 for left, right in zip(body, body[1:], strict=False))
    if adjacent / (len(body) - 1) >= 0.5:
        return False
    if names and _program_name(candidate, body, passphrase=passphrase):
        return False
    counts = Counter(candidate)
    entropy = -sum((count / len(candidate)) * math.log2(count / len(candidate)) for count in counts.values())
    return entropy >= 3.0


def _random_key_body(body: str) -> bool:
    """Require a short sk- key body to mix letters and digits and look random.

    Hyphenated words (``sk-folding-cube-spinner-wrap``) and ticket branches
    (``sk-1234-fix-the-login-page``) have the shape but not the randomness.
    """
    return (
        any(char.isdigit() for char in body)
        and any(char.isalpha() for char in body)
        and sum(char in "-_" for char in body) <= 2
        and _high_entropy_credential(body)
    )


def keep_file_matches(signatures: Sequence[Signature]) -> list[bool]:
    """Which of one file's signature matches to keep.

    A coding agent's own configuration file belongs to that agent: a broader
    signature from the same vendor matching the same file would count it twice.
    """
    agents = {s.vendor for s in signatures if s.category == "coding-agent" and s.vendor}
    return [s.category == "coding-agent" or s.vendor not in agents for s in signatures]


def _generic_literal(value: str, *, code: bool, follower: str, env_file: bool = False) -> str | None:
    """The literal a generic match reports, or None when it holds no key-shaped one.

    A literal value reports itself when it looks random; a reference reports
    the key pasted as its variable's name (``_pasted_key_read``), else the
    fallback literal after it, if any (``_fallback_literal``). In an env or
    credential file (``env_file``) a password's value is never another
    variable's name: such a file has no variables to name, only values. A
    template of one (``.env.example``), a Helm values file, a compose file,
    a workflow or a document is no such file: a PASSWORD value there may name
    a setting, a secret or a placeholder (``springDatasourcePassword``,
    ``useExistingSecretKey``), so the name rules still apply.
    """
    if _reference_value(value, code=code, follower=follower):
        return _pasted_key_read(value, follower) or _fallback_literal(value, follower)
    names = code or not env_file or not _assigned_name(value).lower().endswith(_PASSWORD_NAMES)
    if not names and _label_name(value, _assigned_value(value)):
        return None
    return _assigned_value(value) if _high_entropy_credential(value, names=names) else None


def _label_name(value: str, candidate: str) -> bool:
    """Whether a value built like a name is a label: one of its words is label vocabulary or the name's.

    A person's password in an env file can be built like a name
    (``TrustNoOneEverAgain``, ``summer_vacation_beach_2024``), so the name
    rules do not drop it there; a value whose words say what it stands for
    (``KeycloakAdminPassword`` under ``KEYCLOAK_ADMIN_PASSWORD``,
    ``svc1_local_dev_password``, ``change_me_to_a_strong_password``) is a
    label all the same, as ``_label_slug`` reads a word slug.
    """
    if not _name_shaped(candidate):
        return False
    words = {word.lower() for word in _NAME_WORD.findall(candidate) if word.isalpha()}
    name = {word.lower() for word in _NAME_WORD.findall(_assigned_name(value)) if len(word) >= 3}
    return any(_label_word(word) for word in words) or not words.isdisjoint(name)


# Python's environment mapping read as an attribute ('os.environ.<NAME>'),
# which no evidence pass reads as a lookup: it raises, but its name is still
# written in the code.
_ENVIRON_ATTRIBUTE = re.compile(r"os\.environ\.(?P<name>[A-Z_][A-Z0-9_]*+)")


def _pasted_key_read(value: str, follower: str) -> str | None:
    """The key pasted in place of the variable's name in an environment read, or None.

    'process.env.JBSWY3DPEHPK3PXP...' or 'os.environ.QWERTYUIOP...' reads
    no variable: the name is the credential, written into the code. The
    test is the redactor's (``pasted_key_name``), which withholds the same
    read from evidence, so a credential withheld there is reported here.
    """
    candidate = _assigned_value(value)
    name = environment_read_name(candidate + follower)
    if name is None:
        attribute = _ENVIRON_ATTRIBUTE.fullmatch(candidate)
        name = attribute["name"] if attribute else None
    return name if name is not None and pasted_key_name(name) else None


# The generic patterns' names whose value a person chose (DB_PASSWORD,
# SERVICE_CREDENTIAL), as opposed to the tokens a service issues (API_KEY,
# ACCESS_TOKEN, CLIENT_SECRET).
_PASSWORD_NAMES = ("password", "credential")


def reported_credential(match: Match) -> str:
    """The credential a secret match stands for: a generic match's literal, or the match itself.

    ``OPENAI_KEY=ghp_...`` read as a line and ``ghp_...`` read as that line's
    parsed value are one credential, however the match was cut. A generic
    match of a reference stands for the fallback literal after it, which
    ``match_secrets`` records as ``extra["credential"]``: that literal, not
    the reference, is what a placeholder test judges and what a finding
    counts.
    """
    credential = match.extra.get("credential")
    if isinstance(credential, str):
        return credential
    return _assigned_value(match.value) if match.signature_id == GENERIC_CREDENTIAL else match.value


class _CredentialJudge:
    """Judges each regex match of a secret signature as ``match_secrets`` finds it.

    Called with (signature, signal, match), it says whether the match is a
    credential the quota should count. A second match of a signature over text
    one of its matches already covers is the same credential; a generic match
    that holds no key-shaped literal (``_generic_literal``) is none, nor is a
    short ``sk-`` value that does not look random or that a counted generic
    assignment covers (the rules ``keep_secret_matches`` applies). With
    ``placeholder`` (the caller's documentation-sample test, run on the
    credential a match stands for) a sample counts toward nothing either: up
    to :data:`MAX_SECRETS_PER_SIGNAL` of them per signature are kept in
    ``samples`` for the caller's example evidence, and the rest are dropped,
    since none of them is reported. ``accepted`` holds the spans counted or
    kept per signature, a bounded number.

    The quota counts distinct credentials: a credential a signature already
    counted, repeated on another line (one password in each service of a
    compose file, one key in each document of a manifest), is the same
    credential and counts again toward nothing. It is recognized by a digest
    keyed with a secret of this judge alone (``_seen``), so no credential is
    kept past its match, and the digests cannot be compared with another
    text's.
    """

    def __init__(
        self,
        text: str,
        code: bool,
        placeholder: Callable[[str], object] | None = None,
        *,
        env_file: bool = False,
    ) -> None:
        self.text, self.code, self.placeholder, self.env_file = text, code, placeholder, env_file
        self.accepted: dict[str, list[tuple[int, int]]] = {}
        self.samples: list[tuple[Signature, Signal, Any]] = []
        self._kept_samples: Counter[str] = Counter()
        self._key = os.urandom(32)
        self._seen: set[bytes] = set()

    def _repeated(self, signature_id: str, credential: str) -> bool:
        """Whether ``signature_id`` already counted ``credential``; records it when not."""
        keyed = hashlib.blake2b(f"{signature_id}\0{credential}".encode(), key=self._key, digest_size=16)
        digest = keyed.digest()
        if digest in self._seen:
            return True
        self._seen.add(digest)
        return False

    def _covered(self, signature_id: str, start: int, end: int) -> bool:
        spans = self.accepted.get(signature_id, ())
        return any(start < other_end and other_start < end for other_start, other_end in spans)

    def __call__(self, signature: Signature, signal: Signal, match: Any) -> bool:
        start, end = match.span()
        if self._covered(signature.id, start, end):
            return False
        credential: str | None = match.group(0)
        if signature.id == GENERIC_CREDENTIAL:
            follower = self.text[end : end + _FOLLOWER_CHARS]
            credential = _generic_literal(
                match.group(0), code=self.code, follower=follower, env_file=self.env_file
            )
        elif signature.id == UNATTRIBUTED_KEY and len(match.group(0)) - len("sk-") < _SHORT_KEY_BODY:
            body = match.group(0)[len("sk-") :]
            if self._covered(GENERIC_CREDENTIAL, start, end) or not _random_key_body(body):
                credential = None
        if credential is None:
            return False
        if self.placeholder is not None and self.placeholder(credential):
            if self._kept_samples[signature.id] < MAX_SECRETS_PER_SIGNAL:
                self._kept_samples[signature.id] += 1
                self.accepted.setdefault(signature.id, []).append((start, end))
                self.samples.append((signature, signal, match))
            return False
        if self._repeated(signature.id, credential):
            return False
        self.accepted.setdefault(signature.id, []).append((start, end))
        return True


def _sample_matches(text: str, samples: Sequence[tuple[Signature, Signal, Any]]) -> list[Match]:
    """The documentation samples a ``_CredentialJudge`` kept, as matches of ``text``."""
    if not samples:
        return []
    newlines = [newline.start() for newline in re.finditer("\n", text)]
    return [
        Match(
            signature,
            signal,
            match.group(0),
            signal.weight,
            line=bisect_left(newlines, match.start()) + 1,
            extra={"start": match.start(), "end": match.end()},
        )
        for signature, signal, match in samples
    ]


def keep_secret_matches(
    matches: Sequence[tuple[str, str, int | None]],
    *,
    code: bool = False,
    followers: Sequence[str] | None = None,
    env_file: bool = False,
) -> list[bool]:
    """Which ``(signature id, value, line)`` secret matches to keep.

    A generic assigned-credential match is kept only when its value is a
    literal that looks random and no specific credential pattern matched the
    same value on the same line: ``OPENAI_API_KEY=sk-...`` is one OpenAI key,
    not two findings. A value that only names a credential is not one (see
    ``_reference_value``: ``code`` says the text is source code, and
    ``followers`` holds the text after each match, '' at the end), unless the
    operands after the reference hold a literal key (``_fallback_literal``).
    ``env_file`` says the text is an env or credential file, where a
    password's value names nothing (``_generic_literal``). A short
    unattributed ``sk-`` value only adds keys nothing else reports: it is
    kept when it looks random and no kept generic match covers it.
    """
    credentials = _kept_credentials(matches, code=code, followers=followers, env_file=env_file)
    return [credential is not None for credential in credentials]


def _kept_credentials(
    matches: Sequence[tuple[str, str, int | None]],
    *,
    code: bool = False,
    followers: Sequence[str] | None = None,
    env_file: bool = False,
) -> list[str | None]:
    """The credential each match of ``keep_secret_matches`` stands for, or None where it is not kept.

    A generic match stands for its literal: the value it assigns, or the
    fallback literal after a reference. Any other match stands for itself.
    """
    after = list(followers) if followers is not None else [""] * len(matches)
    short = [
        signature_id == UNATTRIBUTED_KEY and len(value) - len("sk-") < _SHORT_KEY_BODY
        for signature_id, value, _ in matches
    ]
    specific: dict[int | None, list[str]] = {}
    for (signature_id, value, line), is_short in zip(matches, short, strict=True):
        if signature_id != GENERIC_CREDENTIAL and not is_short:
            specific.setdefault(line, []).append(value)
    kept: list[str | None] = []
    generic: dict[int | None, list[str]] = {}
    for (signature_id, value, line), follower in zip(matches, after, strict=True):
        if signature_id != GENERIC_CREDENTIAL:
            kept.append(value)
            continue
        literal = _generic_literal(value, code=code, follower=follower, env_file=env_file)
        others = specific.get(line, ())
        if literal is None or any(other in value or other in literal or literal in other for other in others):
            kept.append(None)
            continue
        kept.append(literal)
        generic.setdefault(line, []).extend((value, literal))
    for position, ((_, value, line), is_short) in enumerate(zip(matches, short, strict=True)):
        if is_short:
            covered = any(value in other for other in generic.get(line, ()))
            kept[position] = None if covered or not _random_key_body(value[len("sk-") :]) else value
    return kept


# ------------------------------------------------------- domain prefilters
# A plain host is lower-case ASCII made of ``[a-z0-9.-]`` with no port, path
# or newline: every token the text tokenizer produces. For such hosts ``$``
# means end of string, ``\.`` means a dot and an ASCII literal matches only
# itself under IGNORECASE, so the required ending or beginning of an anchored
# ``re:`` domain value can be read off its literal characters. Anything the
# shape scanner does not understand stays unkeyed and runs for every host;
# every rejection is therefore conservative and results stay identical.
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
_ALLOWED_ESCAPES = frozenset("dwsDWSbBAZntr")
_GROUP_OPENER_RX = re.compile(r"\(\?(?::|=|!|<=|<!|P<[A-Za-z_]\w*>|<[A-Za-z_]\w*>|[ims-]+[:)])")
_BRACE_QUANTIFIER_RX = re.compile(r"\{\d*(?:,\d*)?\}")
_ORDER = itemgetter(0)


class _HostHints(NamedTuple):
    impossible: bool = False  # the pattern requires ``:`` or ``/``, which no plain host contains
    suffix: str | None = None  # every match ends with ``.<suffix>`` or equals ``<suffix>``
    prefix: str | None = None  # every match starts with ``<prefix>.``


def _escaped_at(pattern: str, index: int) -> bool:
    """Whether an odd run of backslashes precedes ``pattern[index]``."""
    count = 0
    while index - count - 1 >= 0 and pattern[index - count - 1] == "\\":
        count += 1
    return count % 2 == 1


def _plain_shape(pattern: str) -> bool:
    """Accept only syntax whose structure the hint scanners understand.

    Top-level alternation (``$`` would bind to one branch only), inline flags
    other than ``ims``, fuzzy or malformed braces, POSIX classes and escapes
    beyond the common ASCII classes are rejected.
    """
    depth = 0
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                return False
            following = pattern[i + 1]
            if following.isalnum() and following not in _ALLOWED_ESCAPES:
                return False
            i += 2
        elif in_class:
            if c == "]":
                in_class = False
            elif c == "[" and pattern[i + 1 : i + 2] in {":", ".", "="}:
                return False
            i += 1
        elif c == "[":
            in_class = True
            i += 1
            if pattern[i : i + 1] == "^":
                i += 1
            if pattern[i : i + 1] == "]":
                i += 1
        elif c == "(":
            if pattern[i + 1 : i + 2] == "?":
                opener = _GROUP_OPENER_RX.match(pattern, i)
                if opener is None:
                    return False
                i = opener.end()
                if pattern[i - 1] != ")":
                    depth += 1
            else:
                depth += 1
                i += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
            i += 1
        elif c == "|" and depth == 0:
            return False
        elif c == "{":
            quantifier = _BRACE_QUANTIFIER_RX.match(pattern, i)
            if quantifier is None:
                return False
            i = quantifier.end()
        else:
            i += 1
    return depth == 0 and not in_class


def _anchored_prefix(pattern: str) -> str | None:
    """First label every match must start with, from ``^label\\.`` with no quantifier."""
    if not pattern.startswith("^"):
        return None
    i = 1
    while i < len(pattern) and pattern[i] in _LABEL_CHARS:
        i += 1
    if i == 1 or pattern[i : i + 2] != "\\." or pattern[i + 2 : i + 3] in {"?", "*", "+", "{"}:
        return None
    return pattern[1:i].lower()


def plain_host_hints(pattern: str) -> _HostHints:
    """Derive what any plain host matched by a domain regex must contain.

    The suffix hint reads the literal labels before a final ``$`` backwards.
    Each accepted character sits at group depth zero with no quantifier after
    it (a quantifier would have stopped the scan first), so it is required.
    Two labels bounded by escaped dots, or by ``^`` on the left, give the
    two-label key; a required ``:`` or ``/`` makes a plain host impossible.
    """
    if not _plain_shape(pattern):
        return _HostHints()
    hints = _HostHints(prefix=_anchored_prefix(pattern))
    if not pattern.endswith("$") or _escaped_at(pattern, len(pattern) - 1):
        return hints
    labels: list[str] = []
    current: list[str] = []
    i = len(pattern) - 2
    while i >= 0:
        c = pattern[i]
        escaped = _escaped_at(pattern, i)
        if not escaped and c in _LABEL_CHARS:
            current.append(c)
            i -= 1
            continue
        if not escaped and c in ":/":
            return _HostHints(impossible=True)
        if escaped and c == ".":
            labels.append("".join(reversed(current)).lower())
            current = []
            i -= 2
            if len(labels) == 2:
                break
            continue
        if not escaped and c == "^" and current:
            labels.append("".join(reversed(current)).lower())
        break
    if len(labels) < 2:
        return hints
    return _HostHints(suffix=f"{labels[1]}.{labels[0]}", prefix=hints.prefix)


def _last_two_labels(host: str) -> str | None:
    tail = host.rsplit(".", 2)
    return f"{tail[-2]}.{tail[-1]}" if len(tail) > 1 else None


# ------------------------------------------------------- literal prefilter
# Escapes that stand for the escaped character itself in every regex flavour
# this matcher runs; ``\<`` and ``\>`` are left out as some engines treat
# them as word boundaries.
_PUNCT_ESCAPES = frozenset(".()[]{}*+?|^$\\/-:\"'@#,;= ")
_CONTROL_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}
_INLINE_IGNORECASE_RX = re.compile(r"\(\?[a-zA-Z-]*i")


def _fold(text: str) -> str:
    """Casefold consistently with the regex engine's IGNORECASE.

    ``str.casefold`` maps U+0130 (capital I with dot) to two code points and
    leaves U+0131 (dotless i) unchanged, whereas the regex engine treats both
    as equivalent to ``i``; folding them to ``i`` keeps the literal prefilter
    sound for every text the engine would match.
    """
    return text.casefold().replace("i\u0307", "i").replace("\u0131", "i")


_LEADING_FLAGS_RX = re.compile(r"\(\?([ims]+)\)")
_QUANTIFIER_STARTS = frozenset("*+?{")
_GROUP_STOP_CHARS = frozenset("()[].^$*+?{")


class _LiteralHints(NamedTuple):
    """What every match of a pattern must contain: each group holds alternatives, one of which appears.

    ``fold`` marks a case-insensitive pattern whose literals are casefolded
    and must be tested against a casefolded text.
    """

    fold: bool = False
    groups: tuple[tuple[str, ...], ...] = ()


def _literal_alternatives(pattern: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Parse ``(a|b)`` or ``(?:a|b)`` at ``start`` when every alternative is a plain literal.

    Returns the alternatives and the index of the closing parenthesis, or
    None for lookarounds, named or flagged groups, nested constructs, classes,
    quantifiers and empty alternatives.
    """
    i = start + 1
    if pattern.startswith("?:", i):
        i += 2
    elif pattern[i : i + 1] == "?":
        return None
    alternatives: list[str] = []
    current: list[str] = []
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            following = pattern[i + 1 : i + 2]
            literal = following if following in _PUNCT_ESCAPES else _CONTROL_ESCAPES.get(following)
            if literal is None:
                return None
            current.append(literal)
            i += 2
        elif c == ")":
            alternatives.append("".join(current))
            return (tuple(alternatives), i) if all(alternatives) else None
        elif c == "|":
            alternatives.append("".join(current))
            current = []
            i += 1
        elif c in _GROUP_STOP_CHARS:
            return None
        else:
            current.append(c)
            i += 1
    return None


def required_literal(pattern: str) -> str | None:
    """Return the longest single literal every match of a case-sensitive ``pattern`` must contain, or None."""
    hints = required_literals(pattern)
    if hints.fold:
        return None
    return max((group[0] for group in hints.groups if len(group) == 1), key=len, default=None)


def required_literals(pattern: str) -> _LiteralHints:
    """Derive literals every match of ``pattern`` must contain, in pattern order.

    Each run of literal characters at group depth zero is required. A
    character followed by ``?``, ``*`` or a zero-minimum brace quantifier is
    optional and ends a run without joining it; ``+`` and ``{n,}`` keep the
    character but end the run, since the repeat may separate it from what
    follows. A depth-zero group of plain literal alternatives that is not
    optional requires one of its alternatives. A leading ``(?i)`` makes the
    comparison casefolded. Top-level alternation, other case-insensitive
    flags and syntax the shape scanner rejects yield no hints, so the caller
    runs the regex.
    """
    if not _plain_shape(pattern):
        return _LiteralHints()
    fold = False
    i = 0
    flags = _LEADING_FLAGS_RX.match(pattern)
    if flags is not None:
        fold = "i" in flags.group(1)
        i = flags.end()
    if _INLINE_IGNORECASE_RX.search(pattern, i):
        return _LiteralHints()
    groups = _LiteralScanner(pattern).scan(i)
    if fold:
        return _LiteralHints(True, tuple(tuple(_fold(alt) for alt in group) for group in groups))
    return _LiteralHints(False, groups)


def _brace_requires_one(pattern: str, position: int) -> bool:
    """Whether the brace quantifier at ``position`` requires at least one repetition."""
    brace = _BRACE_QUANTIFIER_RX.match(pattern, position)
    minimum = brace.group(0)[1:-1].split(",")[0] if brace is not None else ""
    return bool(minimum) and int(minimum) >= 1


class _LiteralScanner:
    """The single left-to-right pass of ``required_literals`` over a pattern ``_plain_shape`` accepted."""

    __slots__ = ("depth", "groups", "in_class", "pattern", "run")

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.groups: list[tuple[str, ...]] = []
        self.run: list[str] = []
        self.depth = 0
        self.in_class = False

    def scan(self, i: int) -> tuple[tuple[str, ...], ...]:
        """Collect the required literal groups from ``i`` to the end of the pattern."""
        pattern = self.pattern
        n = len(pattern)
        while i < n:
            c = pattern[i]
            if self.in_class:
                if c == "\\":
                    i += 2
                    continue
                if c == "]":
                    self.in_class = False
                i += 1
            elif self.depth > 0:
                i = self._nested(i, c)
            else:
                i = self._top_level(i, c)
        self._flush()
        return tuple(self.groups)

    def _flush(self) -> None:
        if self.run:
            self.groups.append(("".join(self.run),))
        self.run = []

    def _nested(self, i: int, c: str) -> int:
        """Step over one element inside a group that yields no hints."""
        if c == "\\":
            return i + 2
        if c == "[":
            self.in_class = True
            return self._open_class(i)
        if c == "(":
            self.depth += 1
        elif c == ")":
            self.depth -= 1
        return i + 1

    def _top_level(self, i: int, c: str) -> int:
        """Step over one element at group depth zero, recording what it requires."""
        pattern = self.pattern
        literal: str | None = None
        width = 1
        if c == "\\":
            following = pattern[i + 1]
            width = 2
            if following in _PUNCT_ESCAPES:
                literal = following
            else:
                literal = _CONTROL_ESCAPES.get(following)
        elif c == "[":
            self._flush()
            self.in_class = True
            return self._open_class(i)
        elif c == "(":
            self._flush()
            parsed = _literal_alternatives(pattern, i)
            if parsed is not None:
                alternatives, close = parsed
                return self._require(alternatives, close + 1)
            self.depth += 1
            return i + 1
        elif c in _QUANTIFIER_STARTS:
            self._flush()
            return self._skip_quantifier(i)
        elif c not in ".^$)":
            literal = c
        if literal is None:
            self._flush()
            return i + width
        return self._literal(literal, i + width)

    def _literal(self, literal: str, position: int) -> int:
        """Record ``literal`` according to the quantifier, if any, at ``position``."""
        after = self.pattern[position : position + 1]
        if after in {"?", "*"}:
            self._flush()
            return self._skip_quantifier(position)
        if after == "{":
            if _brace_requires_one(self.pattern, position):
                self.run.append(literal)
            self._flush()
            return self._skip_quantifier(position)
        if after == "+":
            self.run.append(literal)
            self._flush()
            return self._skip_quantifier(position)
        self.run.append(literal)
        return position

    def _require(self, alternatives: tuple[str, ...], position: int) -> int:
        """Record a group's alternatives unless its quantifier makes it optional; return the next index."""
        after = self.pattern[position : position + 1]
        if after in {"?", "*"}:
            return self._skip_quantifier(position)
        if after == "{":
            if _brace_requires_one(self.pattern, position):
                self.groups.append(alternatives)
            return self._skip_quantifier(position)
        self.groups.append(alternatives)
        return self._skip_quantifier(position) if after == "+" else position

    def _skip_quantifier(self, position: int) -> int:
        """Return the index after a quantifier at ``position`` and its lazy/possessive suffix."""
        pattern = self.pattern
        if pattern[position] == "{":
            brace = _BRACE_QUANTIFIER_RX.match(pattern, position)
            position = brace.end() if brace is not None else position + 1
        else:
            position += 1
        if pattern[position : position + 1] in {"?", "+"}:
            position += 1
        return position

    def _open_class(self, position: int) -> int:
        pattern = self.pattern
        position += 1
        if pattern[position : position + 1] == "^":
            position += 1
        if pattern[position : position + 1] == "]":
            position += 1
        return position


def _ordered_hints(source: Any) -> _LiteralHints:
    hints = required_literals(source) if isinstance(source, str) else _LiteralHints()
    ordered = sorted(
        hints.groups, key=lambda group: (len(group), -max(len(alternative) for alternative in group))
    )
    return _LiteralHints(hints.fold, tuple(ordered))


def _hints_present(groups: tuple[tuple[str, ...], ...], haystack: str, memo: dict[str, bool]) -> bool:
    """Whether every group has an alternative in ``haystack``; ``memo`` caches per literal."""
    for group in groups:
        for alternative in group:
            found = memo.get(alternative)
            if found is None:
                found = memo[alternative] = alternative in haystack
            if found:
                break
        else:
            return False
    return True


class _RegexPlan:
    """Regex signals of one type and language, indexed by their first required literal group.

    ``entries`` keeps pack order (signal, then pattern) so candidate patterns
    run in exactly the order, and with exactly the per-signal quotas, of an
    exhaustive pass. Patterns without literal hints always run.
    """

    __slots__ = ("entries", "folded_first", "folded_literals", "plain_first", "plain_literals", "unhinted")

    def __init__(self, index: SignatureIndex, signal_type: str, language: str | None) -> None:
        self.entries: list[tuple[Signature, Signal, Any, tuple[tuple[str, ...], ...], bool]] = []
        self.unhinted: list[int] = []
        self.plain_first: dict[str, list[int]] = {}
        self.folded_first: dict[str, list[int]] = {}
        for sig, s in index._by_type.get(signal_type, []):
            if language and s.languages and language not in s.languages:
                continue
            literals = index._literals.get(id(s), ())
            for number, rx in enumerate(s.bounded_compiled):
                hints = literals[number] if number < len(literals) else None
                entry = len(self.entries)
                if hints is None or not hints.groups:
                    self.entries.append((sig, s, rx, (), False))
                    self.unhinted.append(entry)
                    continue
                self.entries.append((sig, s, rx, hints.groups[1:], hints.fold))
                first = self.folded_first if hints.fold else self.plain_first
                for alternative in hints.groups[0]:
                    first.setdefault(alternative, []).append(entry)
        self.plain_literals = tuple(self.plain_first)
        self.folded_literals = tuple(self.folded_first)


class LiteralScan:
    """The required literals of the import, code and secret plans found in one text, scanned once.

    ``present`` holds True for every distinct plain first-group literal of the
    three plans that occurs in ``text``; ``folded_present`` does the same for
    the case-folded literals in the one casefolded copy, ``folded_text``. Each
    pass reads its own plan's literals out of these sets, so the text is
    scanned once for the union of the plans' literals instead of once per
    plan, and casefolded at most once. Both dicts also serve as the memo of
    the remaining literal groups, as the per-pass sets did, so after a pass
    they hold False for the remaining-group literals it found absent.
    """

    __slots__ = ("folded_present", "folded_text", "present", "text")

    def __init__(self, text: str, plans: Sequence[_RegexPlan]) -> None:
        self.text = text
        plain: dict[str, None] = {}
        folded: dict[str, None] = {}
        for plan in plans:
            plain.update(dict.fromkeys(plan.plain_literals))
            folded.update(dict.fromkeys(plan.folded_literals))
        self.present = {literal: True for literal in plain if literal in text}
        self.folded_text: str | None = _fold(text) if folded else None
        self.folded_present = (
            {literal: True for literal in folded if literal in self.folded_text}
            if self.folded_text is not None
            else {}
        )


class _PlainHostCandidates:
    """Domain suffixes and regexes bucketed by what a matching plain host must contain.

    Original pack order is kept through the leading index of every entry so
    the first match per signature, and therefore every result, is unchanged.
    """

    __slots__ = ("regex_by_first", "regex_by_key", "regex_unkeyed", "suffix_by_key", "suffix_unkeyed")

    def __init__(
        self,
        suffixes: list[tuple[str, Signature, Signal]],
        regexes: list[tuple[Any, Signature, Signal]],
    ) -> None:
        self.suffix_by_key: dict[str, list[tuple[int, str, str, Signature, Signal]]] = {}
        self.suffix_unkeyed: list[tuple[int, str, str, Signature, Signal]] = []
        for n, (suffix, sig, s) in enumerate(suffixes):
            bare = suffix.lstrip(".")
            key = _last_two_labels(bare)
            bucket = self.suffix_by_key.setdefault(key, []) if key is not None else self.suffix_unkeyed
            bucket.append((n, suffix, bare, sig, s))
        self.regex_by_key: dict[str, list[tuple[int, Any, Signature, Signal]]] = {}
        self.regex_by_first: dict[str, list[tuple[int, Any, Signature, Signal]]] = {}
        self.regex_unkeyed: list[tuple[int, Any, Signature, Signal]] = []
        for n, (rx, sig, s) in enumerate(regexes):
            hints = plain_host_hints(rx.pattern)
            if hints.impossible:
                continue
            if hints.suffix is not None:
                self.regex_by_key.setdefault(hints.suffix, []).append((n, rx, sig, s))
            elif hints.prefix is not None:
                self.regex_by_first.setdefault(hints.prefix, []).append((n, rx, sig, s))
            else:
                self.regex_unkeyed.append((n, rx, sig, s))

    def suffixes(self, key: str | None) -> list[tuple[int, str, str, Signature, Signal]]:
        keyed = self.suffix_by_key.get(key) if key is not None else None
        if not keyed:
            return self.suffix_unkeyed
        if not self.suffix_unkeyed:
            return keyed
        return sorted(keyed + self.suffix_unkeyed, key=_ORDER)

    def regexes(self, key: str | None, first: str) -> list[tuple[int, Any, Signature, Signal]]:
        keyed = self.regex_by_key.get(key) if key is not None else None
        prefixed = self.regex_by_first.get(first)
        if not keyed and not prefixed:
            return self.regex_unkeyed
        merged = [*self.regex_unkeyed, *(keyed or ()), *(prefixed or ())]
        if len(merged) > 1:
            merged.sort(key=_ORDER)
        return merged


_LANG_ALIASES = {
    "py": "python",
    "python": "python",
    "ipynb": "python",
    "js": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "jsx": "javascript",
    "ts": "javascript",
    "tsx": "javascript",
    "mts": "javascript",
    "cts": "javascript",
    "javascript": "javascript",
    "typescript": "javascript",
    "go": "go",
    "rs": "rust",
    "rust": "rust",
    "java": "java",
    "kt": "java",
    "kts": "java",
    "scala": "java",
    "cs": "dotnet",
    "fs": "dotnet",
    "vb": "dotnet",
    "dotnet": "dotnet",
    "rb": "ruby",
    "ruby": "ruby",
    "php": "php",
    "swift": "swift",
    "dart": "dart",
    "c": "c",
    "h": "c",
    "cpp": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "hpp": "cpp",
    "hxx": "cpp",
    "hh": "cpp",
    "ex": "elixir",
    "exs": "elixir",
    "elixir": "elixir",
    "r": "r",
    "rmd": "r",
    "lua": "lua",
}

SOURCE_EXTENSIONS = {
    ".py",
    ".ipynb",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".cs",
    ".fs",
    ".rb",
    ".php",
    ".swift",
    ".dart",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ex",
    ".exs",
    ".r",
    ".rmd",
    ".lua",
}


def language_for_path(path: str) -> str | None:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _LANG_ALIASES.get(ext)


@dataclass(slots=True)
class Match:
    signature: Signature
    signal: Signal
    value: str  # what matched (package name, line excerpt, host...)
    weight: float
    line: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def signature_id(self) -> str:
        return self.signature.id

    def capabilities(self) -> list[str]:
        caps = list(self.signature.capabilities)
        for c in self.signal.capabilities:
            if c not in caps:
                caps.append(c)
        return caps

    @property
    def agent_indicator(self) -> bool:
        return self.signature.agent_indicator or self.signal.agent_indicator


def _prefix_excluded(signal: Signal, norm: str) -> bool:
    """True when a prefix signal explicitly carves ``norm`` out (exact name or sub-prefix)."""
    if any(norm == normalise_package_name(n) for n in signal.exclude_names):
        return True
    return any(norm.startswith(normalise_package_name(p)) for p in signal.exclude_prefixes)


class SignatureIndex:
    """Indexes signatures by signal type for efficient matching."""

    def __init__(self, signatures: list[Signature]):
        self.signatures: dict[str, Signature] = {s.id: s for s in signatures}
        self._dep_exact: dict[tuple[str, str], list[tuple[Signature, Signal]]] = {}
        self._dep_prefix: dict[str, list[tuple[str, Signature, Signal]]] = {}
        self._env_exact: dict[str, list[tuple[Signature, Signal]]] = {}
        self._env_patterns: list[tuple[Signature, Signal]] = []
        self._client_ids: dict[str, list[tuple[Signature, Signal]]] = {}
        self._domains: dict[str, list[tuple[Signature, Signal]]] = {}
        self._domain_suffixes: list[tuple[str, Signature, Signal]] = []
        self._domain_regex: list[tuple[Any, Signature, Signal]] = []
        self._scopes: dict[str, list[tuple[Signature, Signal]]] = {}
        self._iac: dict[str, list[tuple[Signature, Signal]]] = {}
        self._files: list[tuple[Signature, Signal]] = []
        self._by_type: dict[str, list[tuple[Signature, Signal]]] = {}
        # Per compiled pattern, literals every match must contain, keyed by
        # the signal object; cheap substring tests then skip most patterns
        # for most inputs. Single long literals are tested first so a miss
        # costs one search. Signals live as long as the index.
        self._literals: dict[int, list[_LiteralHints]] = {}
        # Synthesized one-line import statements recur in almost every file
        # ("from django.db import models"); their matches are a pure function
        # of the statement, so they are computed once per index.
        self._statement_imports: dict[tuple[str, str | None], tuple[Match, ...]] = {}
        self._statement_chars = 0
        self._statement_lock = threading.Lock()
        self._regex_plans: dict[tuple[str, str | None], _RegexPlan] = {}
        for sig in signatures:
            for s in sig.signals:
                self._by_type.setdefault(s.type, []).append((sig, s))
                if s.bounded_compiled:
                    self._literals[id(s)] = [
                        _ordered_hints(getattr(rx, "pattern", None)) for rx in s.bounded_compiled
                    ]
                if s.type == "dependency":
                    eco = (s.ecosystem or "any").lower()
                    for n in s.names:
                        self._dep_exact.setdefault((eco, normalise_package_name(n)), []).append((sig, s))
                    for p in s.prefixes:
                        self._dep_prefix.setdefault(eco, []).append((normalise_package_name(p), sig, s))
                elif s.type == "env":
                    for n in s.names:
                        self._env_exact.setdefault(n.upper(), []).append((sig, s))
                    if s.patterns:
                        self._env_patterns.append((sig, s))
                elif s.type == "client_id":
                    for n in s.names:
                        self._client_ids.setdefault(n.lower(), []).append((sig, s))
                elif s.type == "domain":
                    for v in s.values:
                        v = v.strip()
                        if v.startswith("re:"):
                            compiled_domain = regex.compile(v[3:], regex.IGNORECASE | regex.VERSION0)
                            self._domain_regex.append((compiled_domain, sig, s))
                            continue
                        v = v.lower()
                        if v.startswith("*."):
                            self._domain_suffixes.append((v[1:], sig, s))
                        elif v.startswith("."):
                            self._domain_suffixes.append((v, sig, s))
                        else:
                            self._domains.setdefault(v, []).append((sig, s))
                elif s.type == "scope":
                    for v in s.values:
                        self._scopes.setdefault(v.lower(), []).append((sig, s))
                elif s.type == "iac":
                    for v in s.values:
                        self._iac.setdefault(v.lower(), []).append((sig, s))
                elif s.type == "file":
                    self._files.append((sig, s))
        self._plain_hosts = _PlainHostCandidates(self._domain_suffixes, self._domain_regex)
        # fnmatch semantics, precompiled: normcase both sides, translate, match.
        # One alternation of every glob rejects the typical file in one pass.
        self._file_globs: list[
            tuple[Signature, Signal, list[tuple[re.Pattern[str], re.Pattern[str] | None]]]
        ] = []
        translated: list[str] = []
        for sig, s in self._files:
            compiled = []
            for g in s.globs:
                whole = fnmatch.translate(os.path.normcase(g))
                tail = fnmatch.translate(os.path.normcase(g[3:])) if g.startswith("**/") else None
                translated.append(whole)
                if tail is not None:
                    translated.append(tail)
                compiled.append((re.compile(whole), re.compile(tail) if tail is not None else None))
            self._file_globs.append((sig, s, compiled))
        self._file_prefilter = re.compile("|".join(translated)) if translated else None

    # ------------------------------------------------------------------ basic
    def get(self, sig_id: str) -> Signature | None:
        return self.signatures.get(sig_id)

    def by_category(self, category: str) -> list[Signature]:
        return [s for s in self.signatures.values() if s.category == category]

    def signals_of_type(self, kind: str) -> list[tuple[Signature, Signal]]:
        """Every (signature, signal) pair of signal type ``kind``, in pack order.

        These are the pairs the matchers run. Unlike ``signatures``, which is
        keyed by id, a signature id shared by two loaded signatures keeps both.
        The list is a copy; changing it leaves the index untouched.
        """
        return list(self._by_type.get(kind, ()))

    def __len__(self) -> int:
        return len(self.signatures)

    def fingerprint(self) -> str:
        """Stable digest of detection semantics; independent of load paths/order."""
        values = []
        for sig in sorted(self.signatures.values(), key=lambda item: item.id):
            value = {f.name: getattr(sig, f.name) for f in fields(sig) if f.name not in {"source", "signals"}}
            value["signals"] = [
                {
                    f.name: getattr(signal, f.name)
                    for f in fields(signal)
                    if f.name not in {"compiled", "bounded_compiled"}
                }
                for signal in sig.signals
            ]
            values.append(value)
        canonical = json.dumps(values, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @contextmanager
    def scan_budget(
        self,
        seconds: float = DEFAULT_SCAN_BUDGET_SECONDS,
        *,
        chars: int | None = None,
        wall_seconds: float | None = None,
    ) -> Iterator[None]:
        """Share one execution budget across all signature operations for an input file.

        ``seconds`` is CPU time of the calling thread, so a thread descheduled
        under contention does not fail its input. ``wall_seconds`` (default
        ``WALL_BUDGET_FACTOR`` times the budget) is an absolute cap on elapsed
        time, so hostile input and the connector deadline still end it.
        Individual regex executions are also preempted by the regex engine. An
        exhausted budget always raises, including after non-matching work.
        ``chars`` declares the input size so each execution's allowance scales
        linearly with it (never below ``REGEX_TIMEOUT_SECONDS``, never beyond
        this budget); without it the strict flat cap applies.
        """
        if not 0 < seconds <= 60:
            raise ValueError("signature scan budget must be greater than zero and at most 60 seconds")
        if wall_seconds is None:
            wall_seconds = seconds * WALL_BUDGET_FACTOR
        elif not seconds <= wall_seconds <= 60 * WALL_BUDGET_FACTOR:
            raise ValueError("signature scan wall cap must be at least the budget and at most 240 seconds")
        token = _SCAN_BUDGET.set(_ScanBudget(seconds, wall_seconds, _SCAN_BUDGET.get()))
        cap_token = None
        if chars is not None and chars > 0:
            scaled = max(REGEX_TIMEOUT_SECONDS, LINEAR_SECONDS_PER_MILLION_CHARS * (chars / 1_000_000))
            cap = min(scaled, seconds)
            outer_cap = _SCAN_EXECUTION_CAP.get()
            if outer_cap is not None:
                cap = min(cap, outer_cap)
            cap_token = _SCAN_EXECUTION_CAP.set(cap)
        try:
            _remaining_timeout()
            yield
            _remaining_timeout()
        finally:
            if cap_token is not None:
                _SCAN_EXECUTION_CAP.reset(cap_token)
            _SCAN_BUDGET.reset(token)

    # ------------------------------------------------------------- matchers
    def match_dependency(self, ecosystem: str, name: str) -> list[Match]:
        eco = ecosystem.lower()
        norm = normalise_package_name(name)
        out: list[Match] = []
        seen: set[str] = set()
        for key in ((eco, norm), ("any", norm)):
            for sig, s in self._dep_exact.get(key, []):
                if sig.id not in seen:
                    seen.add(sig.id)
                    out.append(Match(sig, s, name, s.weight))
        for e in (eco, "any"):
            for prefix, sig, s in self._dep_prefix.get(e, []):
                if norm.startswith(prefix) and sig.id not in seen and not _prefix_excluded(s, norm):
                    seen.add(sig.id)
                    out.append(Match(sig, s, name, s.weight))
        return out

    @contextmanager
    def _input_budget(self) -> Iterator[None]:
        """Preserve a caller's explicit budget or open the default input budget."""
        if _SCAN_BUDGET.get() is not None:
            _remaining_timeout()
            yield
            _remaining_timeout()
            return
        with self.scan_budget():
            yield

    def _regex_plan(self, signal_type: str, language: str | None) -> _RegexPlan:
        plan = self._regex_plans.get((signal_type, language))
        if plan is None:
            plan = self._regex_plans[(signal_type, language)] = _RegexPlan(self, signal_type, language)
        return plan

    def literal_scan(self, text: str, language: str | None) -> LiteralScan:
        """Scan ``text`` once for the literals of its import, code and secret plans.

        Pass the result to ``match_imports``, ``match_code`` and
        ``match_secrets`` for the same text; each then runs exactly the
        patterns it would have selected from its own scan.
        """
        plans = (
            self._regex_plan("import", language),
            self._regex_plan("code", language),
            self._regex_plan("secret", None),
        )
        with self._input_budget():
            return LiteralScan(text, plans)

    def _match_regex_signals(
        self,
        signal_type: str,
        text: str,
        language: str | None = None,
        max_per_signal: int = 3,
        ignore_spans: Sequence[tuple[int, int]] = (),
        scan: LiteralScan | None = None,
        limited: set[str] | None = None,
        accept: Callable[[Signature, Signal, Any], bool] | None = None,
    ) -> list[Match]:
        # One deadline covers the whole signal class even outside filesystem scans.
        with self._input_budget():
            return self._match_regex_signals_with_budget(
                signal_type, text, language, max_per_signal, ignore_spans, scan, limited, accept
            )

    def _match_regex_signals_with_budget(
        self,
        signal_type: str,
        text: str,
        language: str | None,
        max_per_signal: int,
        ignore_spans: Sequence[tuple[int, int]],
        scan: LiteralScan | None = None,
        limited: set[str] | None = None,
        accept: Callable[[Signature, Signal, Any], bool] | None = None,
    ) -> list[Match]:
        """Match the regex signals of one type, at most ``max_per_signal`` per signal.

        ``accept``, when given, judges each regex match (signature, signal, match) as it is
        found; a rejected match is skipped and does not count toward the quota
        or the look past it.

        ``limited``, when given, collects the id of every signature whose
        signal had more matches than its quota: the matcher then looks one
        match past each quota (a single bounded regex step) instead of
        stopping exactly at it, so a caller can disclose that the returned
        matches are a lower bound. Without it the quota is applied silently,
        as it always was for import and code signals.
        """
        out: list[Match] = []
        # Ignore matches beginning inside comments and literals before applying
        # the per-signal quota. A file with many examples must not hide live code.
        newlines: list[int] | None = None
        starts = [start for start, _ in ignore_spans]
        ends = [end for _, end in ignore_spans]

        def excluded(offset: int) -> bool:
            previous = bisect_right(starts, offset) - 1
            return previous >= 0 and offset < ends[previous]

        # A pattern runs only when every group of its required literals occurs
        # in the text. One scan over the distinct first-group literals selects
        # the candidates; their remaining groups are checked with a memo. The
        # casefolded text is built only when a case-insensitive pattern needs it.
        plan = self._regex_plan(signal_type, language)
        candidates, present, folded_text, folded_present = _plan_candidates(plan, text, scan)

        def hinted(rest: Any, fold: bool) -> bool:
            """Whether the pattern's remaining literal groups occur in the text."""
            if not rest:
                return True
            if fold:
                return _hints_present(rest, folded_text or "", folded_present)
            return _hints_present(rest, text, present)

        skip = excluded if starts else None
        current: int | None = None
        hits = 0
        for number in sorted(candidates):
            sig, s, rx, rest, fold = plan.entries[number]
            select = None if accept is None else partial(accept, sig, s)
            if id(s) != current:
                current, hits = id(s), 0
            elif hits >= max_per_signal:
                # The signal's quota is already full. When the caller wants to
                # know about matches the quota hides, a later pattern of the
                # same signal is still given one bounded search, so a credential
                # that only its second pattern recognizes is counted as hidden.
                if limited is not None and sig.id not in limited and hinted(rest, fold):
                    if _finditer(rx, text, sig.id, 1, skip, select):
                        limited.add(sig.id)
                continue
            if not hinted(rest, fold):
                continue
            for m in _quota_matches(rx, text, sig.id, max_per_signal - hits, skip, limited, select):
                if newlines is None:
                    newlines = [newline.start() for newline in re.finditer("\n", text)]
                line = bisect_left(newlines, m.start()) + 1
                excerpt = m.group(0)
                # Never cut away a credential's recognizable context before
                # redaction. Dedicated secret detectors need the raw match
                # to create their redacted evidence/fingerprint downstream.
                value = excerpt if signal_type == "secret" else sanitize_text(excerpt)[:200]
                span = {"start": m.start(), "end": m.end()}
                out.append(Match(sig, s, value, s.weight, line=line, extra=span))
                hits += 1
                if hits >= max_per_signal:
                    break
        return out

    def match_import_statement(self, statement: str, language: str | None) -> tuple[Match, ...]:
        """Import matches for one synthesized statement, cached for the life of the index.

        The returned matches are shared between callers and must not be mutated.
        """
        key = (statement, language)
        cached = self._statement_imports.get(key)
        if cached is not None:
            return cached
        cached = tuple(self.match_imports(statement, language))
        # Module names come from scanned code and the index lives for the
        # process: keep only short statements, within a total text budget.
        if len(statement) <= _STATEMENT_CACHE_MAX_LENGTH:
            with self._statement_lock:
                if (
                    len(self._statement_imports) >= _STATEMENT_CACHE_LIMIT
                    or self._statement_chars + len(statement) > _STATEMENT_CACHE_MAX_CHARS
                ):
                    self._statement_imports.clear()
                    self._statement_chars = 0
                if key not in self._statement_imports:
                    self._statement_imports[key] = cached
                    self._statement_chars += len(statement)
        return cached

    def match_imports(
        self,
        text: str,
        language: str | None,
        ignore_spans: Sequence[tuple[int, int]] = (),
        scan: LiteralScan | None = None,
    ) -> list[Match]:
        return self._match_regex_signals("import", text, language, ignore_spans=ignore_spans, scan=scan)

    def match_code(
        self,
        text: str,
        language: str | None = None,
        ignore_spans: Sequence[tuple[int, int]] = (),
        scan: LiteralScan | None = None,
    ) -> list[Match]:
        return self._match_regex_signals("code", text, language, ignore_spans=ignore_spans, scan=scan)

    def match_secrets(
        self,
        text: str,
        scan: LiteralScan | None = None,
        *,
        code: bool = False,
        limited: set[str] | None = None,
        placeholder: Callable[[str], object] | None = None,
        env_file: bool = False,
    ) -> list[Match]:
        """Credential matches in ``text``, at most :data:`MAX_SECRETS_PER_SIGNAL` per signal.

        ``code`` says the text is source code, ``env_file`` that it is an env
        or credential file, not a template of one (see ``keep_secret_matches``).
        Matches are judged as they are found (``_CredentialJudge``): a value
        that only names a credential ('self.api_key = api_key' in a settings
        module), a short ``sk-`` look-alike, and a credential another pattern
        of the same signal already matched (``TOKEN=ghp_...`` is the
        assignment and the bare token), count toward nothing, so no number of
        them can push a key written further down past the quota. Neither does
        a documentation sample when the caller passes its ``placeholder``
        test, which judges the credential a match stands for
        (``reported_credential``): a few samples per signature are returned
        besides the quota, for example evidence, and a file of them is never
        reported as holding more credentials than the quota.

        The quota bounds the evidence one finding can carry. It also hides
        every further credential of a format once that many have matched, so
        a caller that reports credentials passes ``limited``: it receives the
        ids of the signatures with more accepted matches than the quota and
        can disclose that its count is a lower bound rather than report a
        complete-looking result.
        """
        judge = _CredentialJudge(text, code, placeholder, env_file=env_file)
        matches = self._match_regex_signals(
            "secret",
            text,
            None,
            max_per_signal=MAX_SECRETS_PER_SIGNAL,
            scan=scan,
            limited=limited,
            accept=judge,
        )
        matches.extend(_sample_matches(text, judge.samples))
        ends = [m.extra.get("end") for m in matches]
        followers = [text[end : end + _FOLLOWER_CHARS] if end is not None else "" for end in ends]
        credentials = _kept_credentials(
            [(m.signature_id, m.value, m.line) for m in matches],
            code=code,
            followers=followers,
            env_file=env_file,
        )
        kept = []
        for match, credential in zip(matches, credentials, strict=True):
            if credential is not None:
                # What a placeholder test judges and a finding counts (``reported_credential``).
                match.extra["credential"] = credential
                kept.append(match)
        return kept

    def match_user_agent(self, ua: str) -> list[Match]:
        if not ua:
            return []
        return self._match_regex_signals("user_agent", ua)

    def match_name(self, name: str) -> list[Match]:
        if not name:
            return []
        return self._match_regex_signals("name", name)

    def match_model(self, model: str) -> list[Match]:
        if not model:
            return []
        return self._match_regex_signals("model", model)

    def match_image(self, image: str) -> list[Match]:
        if not image:
            return []
        return self._match_regex_signals("image", image)

    def match_file(self, relpath: str) -> list[Match]:
        rel = relpath.replace("\\", "/")
        key = os.path.normcase(rel)
        base = key.rsplit("/", 1)[-1]
        prefilter = self._file_prefilter
        if prefilter is None or not (prefilter.match(key) or prefilter.match(base)):
            return []
        out: list[Match] = []
        for sig, s, compiled in self._file_globs:
            for whole, tail in compiled:
                if whole.match(key) or whole.match(base) or (tail is not None and tail.match(key)):
                    out.append(Match(sig, s, rel, s.weight))
                    break
        keep = keep_file_matches([m.signature for m in out])
        return [m for m, kept in zip(out, keep, strict=True) if kept]

    def match_env(self, name: str) -> list[Match]:
        out: list[Match] = []
        for sig, s in self._env_exact.get(name.upper(), []):
            out.append(Match(sig, s, name, s.weight))
        for sig, s in self._env_patterns:
            if any(_search(rx, name, sig.id) for rx in s.bounded_compiled):
                out.append(Match(sig, s, name, s.weight))
        return out

    def match_client_id(self, client_id: str) -> list[Match]:
        if not client_id:
            return []
        out = [Match(sig, s, client_id, s.weight) for sig, s in self._client_ids.get(client_id.lower(), [])]
        for sig, s in self._by_type.get("client_id", []):
            if s.bounded_compiled and any(_search(rx, client_id, sig.id) for rx in s.bounded_compiled):
                out.append(Match(sig, s, client_id, s.weight))
        return out

    def match_domain(self, host: str) -> list[Match]:
        if not host:
            return []
        h = host.lower().strip().rstrip(".")
        if "://" in h:
            h = h.split("://", 1)[1]
        h_with_port = h.split("/", 1)[0]
        h = h_with_port.split(":", 1)[0]
        if h == h_with_port and h.isascii() and "\n" not in h:
            # Ports, paths, newlines and non-ASCII keep the exhaustive scan
            # below, where ``$`` and case folding retain full regex semantics.
            return self._match_plain_host(h, _budgeted_search)
        out: list[Match] = [Match(sig, s, h, s.weight) for sig, s in self._domains.get(h, [])]
        for suffix, sig, s in self._domain_suffixes:
            if h.endswith(suffix) or h == suffix.lstrip("."):
                out.append(Match(sig, s, h, s.weight))
        for rx, sig, s in self._domain_regex:
            if _search(rx, h, sig.id) or _search(rx, h_with_port, sig.id):
                out.append(Match(sig, s, h_with_port, s.weight))
        return out

    def _match_plain_host(self, h: str, search: Callable[[Any, str, str, float], Any]) -> list[Match]:
        """Match a plain host (see ``_PlainHostCandidates``) against its candidate signals only."""
        out: list[Match] = [Match(sig, s, h, s.weight) for sig, s in self._domains.get(h, [])]
        key = _last_two_labels(h)
        for _, suffix, bare, sig, s in self._plain_hosts.suffixes(key):
            if h.endswith(suffix) or h == bare:
                out.append(Match(sig, s, h, s.weight))
        regexes = self._plain_hosts.regexes(key, h.partition(".")[0])
        if regexes:
            # One deadline check per host bounds every candidate's timeout.
            timeout = _remaining_timeout()
            for _, rx, sig, s in regexes:
                if search(rx, h, sig.id, timeout):
                    out.append(Match(sig, s, h, s.weight))
        return out

    def match_domains_in_text(
        self, text: str, *, skip_line: Callable[[str], bool] | None = None, source: bool = False
    ) -> list[Match]:
        """Find signature hosts in ``text``; ``skip_line`` names the lines whose hosts do not count.

        A line the predicate accepts (a hosts-file or proxy-rule entry) is passed over, and the same
        host still counts where it occurs on another line. ``source`` says ``text`` is program source,
        where a host is written in a string or a URL: there an MCP host candidate that does not start
        one (`y = mcp.result.no`) is an object's property, not a host.
        """
        with self._input_budget():
            return self._match_domains_in_text_with_budget(text, skip_line, source)

    def _match_domains_in_text_with_budget(
        self, text: str, skip_line: Callable[[str], bool] | None = None, source: bool = False
    ) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines: list[int] | None = None
        # This fixed tokenizer is a single character class, with linear work.
        # A regex iterator's timeout also counts caller work between yields;
        # applying a 100 ms pattern timeout here incorrectly charges all domain
        # lookup/deduplication work to tokenization. The shared input deadline
        # below bounds iteration instead, checked once per 64 tokens so the
        # bookkeeping stays far below the cost of the tokens. User-defined
        # expressions still use preemptive regex-engine timeouts.
        for count, m in enumerate(_HOST_TOKEN_RX.finditer(text)):
            if not (count & 63):
                _remaining_timeout()
            raw = m.group(0)
            if "." not in raw:
                continue
            host = raw.lower().strip(".")
            mcp_path = bool(_MCP_PATH_RX.match(text, m.end()))
            # DNS names are bounded by the protocol. Consume each entire token
            # once (per MCP/non-MCP path) instead of retrying a suffix from
            # every dot on malformed input.
            key = host + "/mcp" if mcp_path else host
            if key in seen or len(host) > 253 or "." not in host:
                continue
            seen.add(key)
            labels = host.split(".")
            if (
                len(labels[-1]) < 2
                or not labels[-1].isalpha()
                or any(
                    not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
                    for label in labels
                )
            ):
                continue
            # Tokens never carry a port, path or newline; only case folding of
            # non-ASCII letters needs the exhaustive path.
            if host.isascii():
                matches = self._match_plain_host(host, _plain_search)
            else:
                matches = self.match_domain(host)
            if not matches:
                continue
            shared = len({match.signature_id for match in matches}) > 1
            if (
                shared
                and not any("mcp" in label for label in labels)
                and any(match.signature_id == _MCP_SIGNATURE for match in matches)
            ):
                # A host shared with another product (and not named for MCP,
                # like mcp.zapier.com) is MCP only on an MCP path.
                matches = [match for match in matches if (match.signature_id == _MCP_SIGNATURE) == mcp_path]
                if not matches:
                    continue
            if any(match.signature_id == _MCP_SIGNATURE for match in matches) and (
                _CODE_AFTER_NAME_RX.match(text, m.end())
                or (
                    source
                    and not mcp_path
                    and not _STRING_OR_URL_BEFORE.search(text, max(0, m.start() - 2), m.start())
                )
            ):
                # `mcp.logger.info("x")`, `mcp.client.is_connected()`, `mcp.session.page = 2` and, in
                # source, `y = mcp.result.no` name an object called mcp in code, not an MCP host.
                matches = [match for match in matches if match.signature_id != _MCP_SIGNATURE]
                if not matches:
                    seen.discard(key)  # the same name may still be a host elsewhere
                    continue
            if newlines is None:
                newlines = [newline.start() for newline in re.finditer("\n", text)]
            line = bisect_right(newlines, m.start()) + 1
            if skip_line is not None:
                # Rule formats lead their lines, so only the start of a (possibly minified) line is read.
                first = newlines[line - 2] + 1 if line > 1 else 0
                last = newlines[line - 1] if line - 1 < len(newlines) else len(text)
                if skip_line(text[first : min(last, first + _SKIP_LINE_CHARS)]):
                    seen.discard(key)  # the host may still be used on another line
                    continue
            matched_signatures: set[str] = set()
            for match in matches:
                if match.signature_id in matched_signatures:
                    continue
                matched_signatures.add(match.signature_id)
                match.line = line
                out.append(match)
        return out

    def match_scope(self, scope: str) -> list[Match]:
        return [Match(sig, s, scope, s.weight) for sig, s in self._scopes.get(scope.lower(), [])]

    def match_iac(self, resource_type: str) -> list[Match]:
        return [Match(sig, s, resource_type, s.weight) for sig, s in self._iac.get(resource_type.lower(), [])]

    def match_envs_in_text(self, text: str) -> list[Match]:
        """Find environment variable style identifiers inside arbitrary text."""
        with self._input_budget():
            return self._match_envs_in_text_with_budget(text)

    def _match_envs_in_text_with_budget(self, text: str) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines: list[int] | None = None
        for m in _ENV_RX.finditer(text):
            _remaining_timeout()
            name = m.group(0)
            if name in seen:
                continue
            seen.add(name)
            matched_signatures: set[str] = set()
            for match in self.match_env(name):
                if match.signature_id in matched_signatures:
                    continue
                matched_signatures.add(match.signature_id)
                if newlines is None:
                    newlines = [newline.start() for newline in re.finditer("\n", text)]
                match.line = bisect_right(newlines, m.start()) + 1
                out.append(match)
        return out


_HOST_TOKEN_RX = re.compile(r"[a-z0-9.-]+", re.IGNORECASE)
# Characters of a line that `match_domains_in_text` hands its `skip_line` predicate.
_SKIP_LINE_CHARS = 256
_STATEMENT_CACHE_LIMIT = 65_536
_STATEMENT_CACHE_MAX_LENGTH = 256
_STATEMENT_CACHE_MAX_CHARS = 4 * 1024 * 1024
# MCP endpoints on a shared API host are path-scoped: GitHub serves its remote
# MCP server at api.githubcopilot.com/mcp/ beside the Copilot API itself.
_MCP_PATH_RX = re.compile(r"(?::\d{1,5})?/(?:mcp|sse)(?=[/?#\"'\s)\]]|$)", re.IGNORECASE)
_MCP_SIGNATURE = "protocol.mcp"
# What follows a dotted name in code and never a host: a call or an index, the rest of a name the host
# tokenizer stops at (an underscore or a non-ASCII letter), or an assignment or comparison.
_CODE_AFTER_NAME_RX = re.compile(r"[(\[_]|[^\W\d_]|[ \t]*=")
# What a host in program source comes right after: a quote, a URL's "//", or the "@" after its user name
# (not a decorator's "@").
_STRING_OR_URL_BEFORE = re.compile(r"(?:[\"'`]|//|\w@)\Z")
# Underscores delimit disjoint alphanumeric groups; neither tokenizer has nested
# ambiguous repetition. Both operate under the shared input deadline.
_ENV_RX = re.compile(r"\b[A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+){1,6}\b")

_index_lock = threading.Lock()
_default_index: SignatureIndex | None = None


def get_index(
    extra_dirs: list[str] | None = None, reload: bool = False, *, allow_override: bool = False
) -> SignatureIndex:
    """Return the process-wide signature index (built lazily)."""
    global _default_index
    with _index_lock:
        if _default_index is None or reload or extra_dirs:
            dirs: list[str | os.PathLike[str]] | None = list(extra_dirs) if extra_dirs else None
            idx = SignatureIndex(load_signatures(extra_dirs=dirs, allow_override=allow_override))
            if not extra_dirs:
                _default_index = idx
            return idx
        return _default_index
