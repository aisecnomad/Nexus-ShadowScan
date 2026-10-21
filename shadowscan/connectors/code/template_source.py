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
stand-in and each one-line tag is dropped. A file that is broken in any other
way still fails with the stand-ins, so it is not a template by this rule. The
rendering is what the scanner then analyzes, so a placeholder added to a
deployed file does not hide the dependencies or imports around it.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
import warnings

# One placeholder or tag on one line, of bounded length: nothing here scans unboundedly.
_PLACEHOLDER = re.compile(r"\{\{[^{}\n]{1,200}\}\}")
_TAG = re.compile(r"\{%-?[^\n]{1,200}?-?%\}")
# A stand-in that is an identifier (a class or key name) and, in a second
# rendering, a number (a JSON value).
_STAND_INS = ("template_value", "0")
# Larger files are not rendered: a template of source is small.
MAX_TEMPLATE_BYTES = 1_000_000


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


def rendered_template(rel: str, text: str) -> str | None:
    """``text`` rendered with stand-ins when it fails to parse only because of Jinja placeholders and tags.

    The rendering replaces each placeholder by one stand-in and drops each tag,
    keeping every line, so line numbers do not move; it is the text a scanner
    can still analyze (a manifest's dependencies, a module's imports). None
    when the file holds no placeholder or tag, parses as written, is a format
    not judged here, or does not parse with any stand-in.
    """
    if len(text) > MAX_TEMPLATE_BYTES or ("{{" not in text and "{%" not in text):
        return None
    if _parses(rel, text) is not False:
        return None
    untagged = _TAG.sub("", text)
    for stand_in in _STAND_INS:
        rendered = _PLACEHOLDER.sub(stand_in, untagged)
        if _parses(rel, rendered):
            return rendered
    return None


def unrendered_template(rel: str, text: str) -> bool:
    """Whether ``text`` fails to parse only because of Jinja placeholders and tags (``rendered_template``)."""
    return rendered_template(rel, text) is not None
