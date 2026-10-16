"""Source-text shaping for the filesystem connector's analysis and excerpts.

These helpers reshape untrusted file text while preserving character offsets
and line numbers: masking comments, quoting the front-matter values coding
agents accept, rewriting notebook magics, separating quoted crawler
user-agent values, and parsing the structured credential context that excerpt
redaction uses (``_structured_context`` / ``_redacted_source``). Patterns
over untrusted text are linear or run on the bounded ``regex`` engine; see
each helper's docstring.
"""

from __future__ import annotations

import ast
import re
import tomllib
from collections.abc import Iterator, Sequence
from typing import Any

import regex
import yaml

from shadowscan.connectors.code.semantic_config import has_template_markers
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded
from shadowscan.utils.jsonc import load_json_lenient_marked as _load_json_lenient_marked
from shadowscan.utils.redaction import SanitizationLimitError, sanitize, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError
from shadowscan.utils.safe_yaml import (
    YAMLIntegrityError,
    YAMLResourceLimitError,
    strict_bounded_safe_load,
)

# One quoted value, matched from its opening quote; none spans a line break.
_QUOTED_VALUE = {
    '"': re.compile(r'"(?:[^"\\\r\n]|\\[^\r\n])*"'),
    "'": re.compile(r"'(?:[^'\\\r\n]|\\[^\r\n])*'"),
}
# The next opening quote of the kinds that can still close on the line.
_QUOTE_START = {kinds: re.compile(f"[{kinds}]") for kinds in ("\"'", '"', "'")}
_CRAWLER_UA_MARK = re.compile("mozilla/", re.IGNORECASE)
_LINE_BREAK = re.compile(r"[\r\n]")


def _quoted_values(text: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    """Yield the spans of the quoted values on the line ``text[start:end]``, left to right.

    A quote that never closes is scanned to the end of the line, passing
    every later quote of its kind as an escaped character, so none of those
    can close either. Each kind therefore fails at most once per line, and
    a planted line of escaped quotes costs linear time, not one scan to the
    end of the line per quote.
    """
    live = "\"'"
    pos = start
    while live:
        quote = _QUOTE_START[live].search(text, pos, end)
        if quote is None:
            return
        value = _QUOTED_VALUE[quote.group(0)].match(text, quote.start(), end)
        if value is None:
            live = live.replace(quote.group(0), "")
            pos = quote.end()
        else:
            yield value.span()
            pos = value.end()


def _crawler_ua_text(text: str) -> tuple[str, str]:
    """Separate quoted crawler UA values from other text, preserving offsets.

    User-agent parsers and crawler lists quote strings such as
    ``Mozilla/5.0 (compatible; HuggingFace-Bot/1.0; +https://huggingface.co/)``;
    the domain there identifies the bot's operator, never use of the
    provider. Only a complete quoted value with the crawler UA shape is
    discounted. Other values on its line, and later uses of the same host,
    must reach domain matching before the matcher deduplicates occurrences.
    Only lines naming ``mozilla/`` are tokenized, each once.
    """
    spans = []
    pos = 0
    while (mark := _CRAWLER_UA_MARK.search(text, pos)) is not None:
        # The line around the mark; ``pos`` is the previous line's end.
        start = max(text.rfind("\n", pos, mark.start()), text.rfind("\r", pos, mark.start()), pos - 1) + 1
        line_break = _LINE_BREAK.search(text, mark.end())
        end = len(text) if line_break is None else line_break.start()
        for value_start, value_end in _quoted_values(text, start, end):
            value = text[value_start + 1 : value_end - 1].lower()
            if (
                value.startswith("mozilla/")
                and "(compatible;" in value
                and ("+https://" in value or "+http://" in value)
                and value.endswith(")")
            ):
                spans.append((value_start, value_end))
        pos = end
    if not spans:
        return text, ""
    content: list[str] = []
    ua: list[str] = []
    previous = 0
    for start, end in spans:
        content.extend((text[previous:start], " " * (end - start)))
        ua.append(text[start:end])
        previous = end
    content.append(text[previous:])
    return "".join(content), "\n".join(ua)


# Agent definition front matter. Only horizontal whitespace may follow a
# marker: ``\s*`` before a required newline backtracks quadratically over a
# run of blank lines, which a planted file makes as long as it likes. The
# possessive quantifier never backtracks, and the bounded engine applies the
# per-input matching budget where the pattern runs (_parse_agent_definition).
_FRONTMATTER = regex.compile(r"^---[ \t\r]*+\n(.*?)\n---[ \t\r]*+\n", regex.S)
# Front-matter keys whose bare glob values _quote_glob_values quotes.
_GLOB_KEYS = ("globs", "paths")
# A YAML comment starts at a "#" that follows a space or tab.
_COMMENT_START = re.compile(r"[ \t]#")
# Files whose parsed structure supplies credential context for excerpt
# redaction (see _structured_context).
_JSON_SUFFIXES = (".json", ".jsonc", ".json5")
_YAML_SUFFIXES = (".yaml", ".yml")


# The span of each code cell in a notebook's text; empty for any other file.
_CellSpans = tuple[tuple[int, int], ...]


# What opens a comment in the languages the lexer masks; every other masked
# span is a string literal, which the model-identifier pass reads.
_COMMENT_OPENERS = ("#", "//", "/*", "<!--", "=begin")


def _comment_spans(text: str, ignored: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """The comment spans among the lexer's ``ignored`` spans of ``text`` (strings are kept)."""
    return [(start, end) for start, end in ignored if text.startswith(_COMMENT_OPENERS, start)]


def _strip_comment(text: str) -> str:
    """Remove a trailing YAML comment and the blanks before it."""
    start = _COMMENT_START.search(text)
    return text if start is None else text[: start.start()].rstrip(" \t")


def _quote_plain_values(front_matter: str) -> str:
    """Quote the top-level plain values that YAML rejects, so the front matter can be parsed again.

    A value is rejected when it contains ": ", ends in ":" or starts with "@", a backtick or "%".
    Generated agent definitions routinely write ``description: Use this agent when: ...`` or
    ``Examples: <example>Context: ...`` unquoted. Coding agents quote such a value and parse the
    front matter again, so this does the same. Only a key at the start of a line followed by a
    one-line plain value is rewritten (flow collections, block scalars, quoted values, anchors,
    aliases and explicit tags are left alone, so they fail as before), and lines are split with
    string methods rather than backtracking patterns: the front matter is untrusted.
    """
    out: list[str] = []
    for raw in front_matter.split("\n"):
        line = raw.rstrip("\r")
        key, colon, rest = line.partition(":")
        # A trailing " #" comment is not part of the value: `model: sonnet # note: fast` is valid as it is.
        value = rest.partition(" #")[0].strip(" \t") if rest[:1] == " " else rest.strip(" \t")
        if (
            colon
            and key
            and rest[:1] in {" ", "\t"}
            and all(character.isalnum() or character in "_-" for character in key)
            and value
            and value[0] not in "\"'|>[{&*!#"
            and (": " in value or value.endswith(":") or value[0] in "@`%")
        ):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            line = f'{key}: "{escaped}"'
        out.append(line)
    return "\n".join(out)


def _quote_glob_values(front_matter: str) -> str:
    """Quote bare ``globs``/``paths`` values that start with ``*``.

    Cursor and Claude Code rule files routinely write ``globs: **/*.ts``
    unquoted, which YAML reads as an alias and rejects. Only those two keys
    (a scalar, a flow list or block list items) are rewritten, so a real alias
    elsewhere is untouched and the bounded loader still parses the result.
    Lines are split with string methods, not backtracking patterns: the front
    matter is untrusted, and the scan budget cannot interrupt stdlib ``re``,
    so a long run of blanks must cost linear time.
    """

    def quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    out: list[str] = []
    in_list = False
    for raw in front_matter.split("\n"):
        line = raw.rstrip("\r")
        head, colon, rest = line.partition(":")
        name = head.rstrip(" \t")
        if colon and name in _GLOB_KEYS:
            value = rest.strip(" \t")
            if value.startswith("#"):
                value = ""
            elif value.startswith("*"):
                value = _strip_comment(value)
            in_list = not value
            if value.startswith("*"):
                raw = f"{name}: {quote(value)}"
            elif (
                value.startswith("[")
                and value.endswith("]")
                and "*" in value
                and not re.search(r"[\"']", value)
            ):
                items = [item.strip() for item in value[1:-1].split(",")]
                raw = f"{name}: [{', '.join(quote(i) if i.startswith('*') else i for i in items)}]"
        elif in_list:
            # A block item is blanks, "-", at least one blank, then the glob.
            item = _strip_comment(line)
            body = item.lstrip(" \t")
            glob = body[1:].lstrip(" \t")
            if body.startswith("-") and glob.startswith("*") and len(glob) < len(body) - 1:
                raw = item[: len(item) - len(glob)] + quote(glob.rstrip(" \t"))
            elif line[:1] not in ("", " ", "\t", "-", "#"):
                in_list = False
        out.append(raw)
    return "\n".join(out)


# IPython line and cell magics (%pip, %%time) and shell escapes (!pip), each
# alone on its line, as IPython rewrites them before Python reads the cell.
# "% name" continuing an expression is the modulo operator and stays.
_IPYTHON_LINE = re.compile(r"^([ \t]*+)((?:%%?[A-Za-z_]|!)[^\n]*)", re.MULTILINE)


def _without_ipython_lines(text: str) -> str:
    """Replace a notebook's magic and shell lines with an inert expression, keeping every offset.

    IPython turns each into an expression statement, so an indented one can be a
    block's only statement: it becomes ``0`` padded to its length, not blanks.
    """
    return _IPYTHON_LINE.sub(lambda match: match[1] + "0" + " " * (len(match[2]) - 1), text)


def _within(offset: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def _cell_noncode_ranges(text: str, cells: _CellSpans) -> tuple[list[tuple[int, int]], bool]:
    """Lex each notebook cell on its own; return the ignored spans in ``text``'s offsets."""
    spans: list[tuple[int, int]] = []
    ambiguous = False
    for start, end in cells:
        cell_spans, cell_ambiguous = noncode_ranges(text[start:end], "python")
        spans.extend((start + low, start + high) for low, high in cell_spans)
        ambiguous = ambiguous or cell_ambiguous
    return spans, ambiguous


# Cell magics whose body is not Python: IPython runs it with another program, renders it, or
# writes it to a file (see ``foreign_cell``). Any other cell magic's body is read as Python.
_FOREIGN_CELL_MAGICS = frozenset(
    {
        "bash", "sh", "zsh", "script", "perl", "ruby", "html", "javascript", "js", "latex",
        "markdown", "svg", "writefile", "file", "sx", "system", "cmd", "powershell", "pwsh", "r",
        "sql", "julia", "octave", "matlab", "cython", "python2",
    }
)  # fmt: skip
_CELL_MAGIC = re.compile(r"\s*+%%([A-Za-z_][\w.]*+)[ \t]*+([^\n]*+)")
_PYTHON_PROGRAM = re.compile(r"python(?:\d+(?:\.\d+)?)?w?(?:\.exe)?", re.IGNORECASE)


def foreign_cell(source: str) -> bool:
    """Whether a notebook cell's body is not Python, by the cell magic that starts it.

    ``%%bash``, ``%%html``, ``%%sql`` and the like run or render another language, and
    ``%%writefile requirements.txt`` writes text. A Python module written with
    ``%%writefile`` and ``%%script python3`` stay Python, as do ``%%time``, ``%%capture``
    and every other cell magic.
    """
    match = _CELL_MAGIC.match(source)
    if match is None:
        return False
    name, arguments = match[1].lower(), match[2].split()
    if name in {"writefile", "file"}:
        target = next((argument for argument in arguments if not argument.startswith("-")), "")
        return not target.strip("\"'").lower().endswith(".py")
    if name == "script":
        program = arguments[0].replace("\\", "/").rsplit("/", 1)[-1] if arguments else ""
        return _PYTHON_PROGRAM.fullmatch(program) is None
    return name in _FOREIGN_CELL_MAGICS


def _notebook_binder_source(text: str, cells: _CellSpans, foreign: _CellSpans = ()) -> tuple[str, list[int]]:
    """Return a notebook's cells as the import binder reads them, and which cells do not parse.

    Magic and shell lines become inert expressions (``_without_ipython_lines``).
    A cell that still does not parse is blanked, its line breaks kept, so the
    other cells are bound together, as Jupyter runs them, and every offset and
    line stays that of ``text``. ``foreign`` cells (another language) are blanked
    without being parsed, so they are not reported as unparsed.
    """
    source = _without_ipython_lines(text)
    unparsed: list[int] = []
    for number, (start, end) in enumerate(cells):
        if (start, end) in foreign:
            continue
        try:
            ast.parse(source[start:end])
        except (SyntaxError, ValueError):
            unparsed.append(number)
        except RecursionError as exc:
            raise SourceBudgetExceeded("source binding recursion limit exceeded") from exc
    masked = sorted({*foreign, *(cells[number] for number in unparsed)})
    return _without_source_ranges(source, masked), unparsed


def _without_source_ranges(text: str, spans: Sequence[tuple[int, int]]) -> str:
    """Mask sorted, disjoint source ranges while preserving every offset and line break."""
    pieces: list[str] = []
    previous = 0
    for start, end in spans:
        pieces.extend((text[previous:start], re.sub(r"[^\n]", " ", text[start:end])))
        previous = end
    pieces.append(text[previous:])
    return "".join(pieces)


def _without_xml_comments(text: str) -> str:
    """Mask XML comments while preserving character offsets and source lines."""
    return re.sub(r"<!--.*?(?:-->|$)", lambda match: re.sub(r"[^\n]", " ", match.group()), text, flags=re.S)


_NO_STRUCTURE = object()


def _structured_context(rel: str, text: str, strict_json: list[bool] | None = None) -> Any:
    """Parse the structure that supplies credential context for excerpt redaction.

    ``strict_json`` receives True when a JSON document was accepted by the
    strict decoder (no comments or trailing commas were stripped).

    Returns ``_NO_STRUCTURE`` for plain text and for structured files whose
    syntax or shape the dedicated parser rejects; lexical redaction then
    applies. Resource-limit and integrity failures (duplicate fields,
    non-finite numbers) propagate: they must reach the per-file isolation
    boundary even when nothing is excerpted, since lexical fallback would
    otherwise disguise an incomplete analysis. An unrendered Helm, Jinja or
    Go template is the exception to the integrity rule: its raw text is not
    YAML, so a placeholder such as ``{{ .Values.image }}`` reads as a mapping
    key and conditional branches repeat fields. It falls back to lexical
    redaction like any other template the parser rejects.
    """
    try:
        if rel.endswith(_JSON_SUFFIXES):
            document, strict = _load_json_lenient_marked(text)
            if strict and strict_json is not None:
                strict_json.append(True)
            return document
        if rel.endswith(".toml"):
            return tomllib.loads(text)
        if rel.endswith(_YAML_SUFFIXES):
            return strict_bounded_safe_load(text, require_string_keys=False)
    except YAMLIntegrityError:
        if has_template_markers(text):
            return _NO_STRUCTURE
        raise
    except (JSONIntegrityError, YAMLResourceLimitError, SanitizationLimitError):
        raise
    except (ValueError, RecursionError, yaml.YAMLError):
        return _NO_STRUCTURE
    return _NO_STRUCTURE


def _redacted_source(text: str, structure: Any) -> str:
    """Redact ``text`` with the structured context from ``_structured_context``, keeping line positions.

    An opaque argv value is identifiable only alongside its flag, and environment
    values must not reappear in source snippets after being removed from metadata.
    """
    if structure is _NO_STRUCTURE:
        return sanitize_text(text)
    try:
        result: str = sanitize((structure, text))[1]
        return result
    except (YAMLResourceLimitError, SanitizationLimitError):
        raise
    except (ValueError, RecursionError, yaml.YAMLError):
        return sanitize_text(text)
