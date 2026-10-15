"""Characters that show nothing are rendered as escapes in human-read output."""

from __future__ import annotations

import pytest

from shadowscan.reporters._publication import visible_controls
from shadowscan.utils.output import terminal_text

INVISIBLE = [
    "­",  # soft hyphen
    "͏",  # combining grapheme joiner
    "᠎",  # Mongolian vowel separator
    "⁪",  # inhibit symmetric swapping
    "️",  # variation selector 16
    "￹",  # interlinear annotation anchor
    "\U000e0101",  # variation selector 18
    "\U0001d173",  # musical symbol begin beam
    "ㅤ",  # Hangul filler
    "⠀",  # blank Braille pattern
]


@pytest.mark.parametrize("char", INVISIBLE)
def test_invisible_characters_are_escaped(char):
    shown = terminal_text(f"a{char}b")
    assert char not in shown and shown.startswith("a\\") and shown.endswith("b")
    assert char not in visible_controls(f"a{char}b")


def test_visible_text_and_kept_whitespace_are_unchanged():
    text = "agent ✓ café 中文 😀 \t line\n"
    assert terminal_text("agent ✓ café 中文 😀") == "agent ✓ café 中文 😀"
    assert visible_controls(text, keep="\t\n") == text
