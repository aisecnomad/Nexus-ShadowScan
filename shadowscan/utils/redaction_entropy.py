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
# module paths, URLs, host names and sentences never qualify.
_QUOTED = re.compile(r"""(?P<q>["'`])(?P<body>[A-Za-z0-9+/_=-]{20,4096})(?P=q)""")  # 20 = _MIN_LENGTH


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
        lambda m: f"{m['q']}{REDACTED}{m['q']}" if looks_random(m["body"]) else m.group(0),
        text,
    )
