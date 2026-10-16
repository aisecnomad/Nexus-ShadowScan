"""Excerpt sources and lazily cut snippet lines for the filesystem connector.

An excerpt is one redacted, sanitized source line. Cutting it is deferred
(``_LazyExcerpt``) until a report retains the evidence, and every line comes
from the redacted text of its file (``_ExcerptSource``), never from the raw
read; see ``FilesystemConnector._settle_excerpts``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shadowscan.utils.redaction import sanitize_text
from shadowscan.utils.redaction_entropy import withhold_random_literals
from shadowscan.utils.text import redact


def _excerpt(lines: list[str], line: int, secret: str | None = None, width: int = 160) -> str:
    """Return one trimmed source line; a matched credential is redacted before truncation.

    Truncating first can leave a recognisable prefix of a long credential in
    the snippet when the full value no longer appears in the shortened text.
    """
    try:
        text = lines[line - 1]
    except IndexError:
        return ""
    text = text.strip()
    if secret:
        text = text.replace(secret, redact(secret))
    # The snippet sanitizer reads only the excerpt: a random-looking literal that the cut
    # shortens below its minimum length would show its start there, so read the whole line.
    text = withhold_random_literals(text)
    return text if len(text) <= width else text[: width - 1] + "…"


@dataclass
class _ExcerptSource:
    """The text one file's excerpts are cut from, redacted once its analysis ends.

    Excerpt lines are cut from the redacted lines of the file and sanitized at
    emit time for the evidence a report keeps. Whether redaction exceeds a
    sanitization limit is known only by redacting, so every file that recorded
    excerpted evidence is redacted when its analysis ends (see
    ``_settle_excerpts``), as the eager excerpts were; its text and redacted
    lines are then dropped and only the excerpts of the ``wanted`` lines are
    kept. ``structure`` is the credential context of ``_structured_context``;
    None withholds every excerpt of the file.
    """

    rel: str
    path: Path
    text: str | None
    structure: Any
    safe_lines: list[str] | None = None  # redacted lines, produced when an excerpt first needs them
    wanted: set[int] = field(default_factory=set)  # lines recorded matches asked excerpts of
    kept: dict[int, str] | None = None  # line -> excerpt, once the file's analysis ended


class _LazyExcerpt:
    """One excerpt line, cut and sanitized only when a report retains its evidence."""

    __slots__ = ("line", "redacted_lines", "source")

    def __init__(
        self,
        redacted_lines: Callable[[_ExcerptSource], list[str]],
        source: _ExcerptSource,
        line: int | None,
    ) -> None:
        self.redacted_lines = redacted_lines
        self.source = source
        self.line = line

    def __call__(self) -> str:
        line = self.line or 1
        if self.source.kept is not None:
            return sanitize_text(self.source.kept.get(line, ""))
        return sanitize_text(_excerpt(self.redacted_lines(self.source), line))


# A recorded snippet: text, an excerpt produced on demand, or none.
_Snippet = str | _LazyExcerpt | None
