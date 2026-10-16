"""Last-resort redaction of random-looking string literals in evidence snippets.

The other redaction passes recognize credentials by provider format or by the
name they are assigned to. A generic credential with neither, such as an
opaque literal passed to an unrecognized call or labelled only by a comment,
passes through them. This pass reads only evidence snippets, which are short
code excerpts, and withholds a quoted literal when it looks random: long,
drawn from a token alphabet, mixing upper case, lower case and digits, often
switching between them, and with high per-character entropy. Hex digests,
UUIDs, identifiers and prose keep their text.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from shadowscan.utils.redaction_rules import REDACTED

_MIN_LENGTH = 20
# Bits per character. A short string's entropy is capped by its length, so the
# floor is a share of that cap, up to 4.0 (random base62 of 32 characters is about 4.6).
_MIN_ENTROPY = 4.0
_MIN_ENTROPY_SHARE = 0.85
# Share of adjacent letters and digits in different classes (upper, lower, digit), separators
# ignored. Random base62 averages about 0.62; camelCase and word-based names stay near 0.3.
_MIN_SWITCH_RATE = 0.45
_MIN_DIGITS = 1
# A quoted run of token characters. Dots, colons and spaces are excluded so
# module paths, URLs, host names and sentences never qualify. The run ends at its
# closing quote, or where an excerpt cut the line (an ellipsis or the end of the
# line): a literal truncated before its closing quote still starts with the secret.
# The closing quote is only looked at, not consumed: in '"v1-"+prefixName2024+"<secret>"'
# the run between two literals is matched first, and a consumed quote hid the secret's
# opening quote. The possessive quantifier keeps the scan linear in the text.
_QUOTED = re.compile(
    r"""(?P<q>["'`])(?P<body>[A-Za-z0-9+/_=-]{20,}+)(?=(?P=q)|\u2026|$)""",  # 20 = _MIN_LENGTH
    re.MULTILINE,
)


def _class(char: str) -> str:
    if char.isdigit():
        return "d"
    return "u" if char.isupper() else "l"


def looks_random(value: str) -> bool:
    """Whether ``value`` has the shape of a generated secret rather than a name or digest."""
    if len(value) < _MIN_LENGTH:
        return False
    if not (any(c.isupper() for c in value) and any(c.islower() for c in value)):
        return False
    if sum(c.isdigit() for c in value) < _MIN_DIGITS:
        return False
    classes = [_class(c) for c in value if c.isalnum()]
    switches = sum(left != right for left, right in zip(classes, classes[1:], strict=False))
    if switches / (len(classes) - 1) < _MIN_SWITCH_RATE:
        return False
    counts = Counter(value)
    entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
    return entropy >= min(_MIN_ENTROPY, _MIN_ENTROPY_SHARE * math.log2(len(value)))


def withhold_random_literals(text: str) -> str:
    """Replace the body of every random-looking quoted literal in ``text`` with the redaction marker."""
    return _QUOTED.sub(
        lambda m: f"{m['q']}{REDACTED}" if looks_random(m["body"]) else m.group(0),
        text,
    )


# How far past the shown part of a cut line ``withhold_random_literals_cut`` reads.
_CUT_LOOKAHEAD = 256


def withhold_random_literals_cut(text: str, width: int) -> str:
    """``withhold_random_literals(text)`` cut to ``width`` characters, an ellipsis marking a cut.

    A literal is judged before the cut, since one the cut shortened below the minimum length
    would show its start to a later pass. Only a literal that starts in the shown part can
    appear there, so a long line is read only up to the shown part and a lookahead past it,
    keeping the cost proportional to the excerpt rather than to the line (a minified bundle
    line can be a megabyte, cut once per match). A shown literal is judged on its whole body
    or, when it runs past the lookahead, on the part read; a withheld literal that runs past
    the part read ends the excerpt, since where it ends is not read. Withheld literals shorten
    the text, so the part read moves on with each literal rather than being one fixed window,
    which could end inside a literal the shortened excerpt then shows unjudged.
    """
    if len(text) <= width + _CUT_LOOKAHEAD:
        text = withhold_random_literals(text)
        return text if len(text) <= width else text[: width - 1] + "\u2026"
    shown: list[str] = []
    size = 0
    pos = 0
    # Build up to ``width + 1`` characters: more than ``width`` means the line is cut.
    while size <= width and pos < len(text):
        room = width + 1 - size
        end = pos + room + _CUT_LOOKAHEAD
        match = _QUOTED.search(text, pos, end)
        if match is None or match.start() >= pos + room:
            shown.append(text[pos : pos + room])
            size += min(room, len(text) - pos)
            pos += room
            continue
        shown.append(text[pos : match.start()])
        size += match.start() - pos
        literal = match.group(0)
        if looks_random(match["body"]):
            literal = f"{match['q']}{REDACTED}"
            if match.end() == end < len(text):
                return ("".join(shown) + literal)[: width - 1] + "\u2026"
        shown.append(literal)
        size += len(literal)
        pos = match.end()
    result = "".join(shown)
    return result if size <= width and pos >= len(text) else result[: width - 1] + "\u2026"
