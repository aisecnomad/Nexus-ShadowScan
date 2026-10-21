"""Recognize unrendered Jinja template source by its content.

Project generators (crewAI's ``crewai create``, cookiecutter, copier) ship
files that are templates of source rather than source: ``class
{{crew_name}}():`` is not Python and ``{{folder_name}} = "..."`` is not TOML
until the generator fills the placeholder in. A directory whose name holds
template syntax already marks its files as templates (``walk._TEMPLATE_SYNTAX``);
a template kept under an ordinary name (``templates/crew/crew.py``) is
recognized here instead, by rendering it with stand-ins.

The rule is narrow on purpose. The file must fail its own parser, hold Jinja
placeholders or tags, and parse once each placeholder is replaced by a
stand-in and each tag line is blanked. A file that is broken in any other
way still fails with the stand-ins, so it is not a template by this rule. The
rendering is what the scanner then analyzes, so a placeholder added to a
deployed file does not hide the dependencies or imports around it.

Neither a placeholder nor a tag can swallow the structure around it. A
placeholder holds a Jinja expression without quotes, separators or brackets
(``{{ cookiecutter.package_name }}``, ``{{ name | lower }}``), so it cannot
span from one string or value to another; a tag is a line of its own
(``{%- if cookiecutter.depends_on_core -%}``) with no ``%}`` before its end.
A ``package.json`` whose ``dependencies`` sit between ``"{%`` and ``%}"`` on
one line is not rendered: it fails to parse, as it would without this rule.
"""

from __future__ import annotations

import ast
import functools
import json
import re
import tomllib
import warnings

# One placeholder within a line, or one tag that is a whole line, of bounded length:
# nothing here scans unboundedly. A placeholder's expression holds no quote, separator,
# bracket, assignment, comment or line break (a bare CR ends a Python line too), so it
# cannot reach across a string, a value or a statement.
_PLACEHOLDER = re.compile(r"\{\{[^{}\r\n\"'`,;:=#\[\]]{1,200}\}\}")
_TAG = re.compile(r"^[ \t]*+\{%(?:[^%\r\n]|%(?!\})){1,200}%\}[ \t]*+(?=\r?$)", re.MULTILINE)
# Larger files are not rendered: a template of source is small.
MAX_TEMPLATE_BYTES = 1_000_000


def _identifier(placeholder: re.Match[str]) -> str:
    """A stand-in identifier (a class or key name) of the placeholder's length."""
    return "t" + "_" * (len(placeholder.group()) - 1)


def _number(placeholder: re.Match[str]) -> str:
    """A stand-in number (a JSON value) of the placeholder's length."""
    return "0" + " " * (len(placeholder.group()) - 1)


def _blank(tag: re.Match[str]) -> str:
    return " " * len(tag.group())


# Every stand-in is as long as what it replaces, so each character of the rendering
# keeps its offset in the file: spans the binder finds in the rendering locate the
# file's own lexical matches.
_STAND_INS = (_identifier, _number)


def _parses(rel: str, text: str) -> bool | None:
    """Whether ``text`` parses as the format ``rel`` names; None for a format not judged here."""
    lower = rel.lower()
    try:
        if lower.endswith((".py", ".pyi")):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ast.parse(text)
        elif lower.endswith(".toml"):
            tomllib.loads(text)
        elif lower.endswith(".json"):
            json.loads(text)
        else:
            return None
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return True


@functools.lru_cache(maxsize=8)
def rendered_template(rel: str, text: str) -> str | None:
    """``text`` rendered with stand-ins when it fails to parse only because of Jinja placeholders and tags.

    The rendering replaces each placeholder by a stand-in of its length and
    each tag by blanks, so neither a line number nor a character offset moves;
    it is the text a scanner can still analyze (a manifest's dependencies, a
    module's imports). None when the file holds no placeholder or tag, parses
    as written, is a format not judged here, or does not parse with any
    stand-in. The file scanner asks for one file's rendering more than once,
    so recent renderings are kept rather than parsed again.
    """
    if len(text) > MAX_TEMPLATE_BYTES or ("{{" not in text and "{%" not in text):
        return None
    if _parses(rel, text) is not False:
        return None
    untagged = _TAG.sub(_blank, text)
    # Python takes an identifier wherever it takes a number, so it is rendered once.
    for stand_in in _STAND_INS[:1] if rel.lower().endswith((".py", ".pyi")) else _STAND_INS:
        rendered = _PLACEHOLDER.sub(stand_in, untagged)
        if _parses(rel, rendered):
            return rendered
    return None


def unrendered_template(rel: str, text: str) -> bool:
    """Whether ``text`` fails to parse only because of Jinja placeholders and tags (``rendered_template``)."""
    return rendered_template(rel, text) is not None
