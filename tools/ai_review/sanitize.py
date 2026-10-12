"""Redaction for anything the AI Review Gate posts or logs.

Review findings quote pull-request content, which is untrusted. Before a
finding leaves the runner, every posted string passes through ``redact``,
which removes strings shaped like common credentials and neutralizes GitHub
workflow-command lines. The patterns mirror tools/check_secrets.py closely
enough for posted text; check_secrets.py stays the authoritative gate for
files, because its approvals bind exact paths and digests.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![\w-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}"),
    re.compile(r"(?<![\w-])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(
        r"(?i:(?:aws_?)?secret_?access_?key)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
    ),
    re.compile(r"(?<![\w])gh[pousr]_[A-Za-z0-9]{36,251}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w-])glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox[abeoprs]-\d+-[0-9A-Za-z-]{10,}"),
    re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),
    re.compile(r"(?<![\w])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w])[rs]k_live_[0-9A-Za-z]{20,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # The whole block. With a footer within 8 KiB, everything up to it, however the body is
    # quoted (real or escaped line breaks, one line, a '> ' prefix). Without one, the header,
    # PEM encryption headers directly after it, at most one blank line, then runs of 16 or more
    # base64 characters separated by spaces (a footerless key quoted on one line) or by line
    # breaks: real or escaped ('\n', '\r\n'), each followed by any Markdown blockquote markers
    # ('> '), so prose after a quoted header line is kept. An encryption header that follows an
    # escaped break ends at the next escaped break. Only a header can start a match, and the
    # footer search is bounded.
    re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"|(?:\r?\n(?:[ \t]*>)*[ \t]*(?:Proc-Type|DEK-Info):[^\r\n]*"
        r"|(?:\\r)?\\n(?:[ \t]*>)*[ \t]*(?:Proc-Type|DEK-Info):(?:[^\r\n\\]|\\(?!(?:r\\)?n))*)*"
        r"(?:(?:(?:\r?\n|(?:\\r)?\\n)(?:[ \t]*>)*[ \t]*)?"
        r"(?:(?:(?:\r?\n|(?:\\r)?\\n)(?:[ \t]*>)*[ \t]*|[ \t]+)[A-Za-z0-9+/=]{16,})+)?)"
    ),
    re.compile(r"(?i:\b(?:Account|SharedAccess)Key)\s*=\s*[A-Za-z0-9+/]{40,}={0,2}"),
    re.compile(
        r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://"
        r"[^\s/:@'\"<>]+:[^\s/@'\"<>]+@[^\s/'\"<>]"
    ),
)

_REDACTED = "[redacted]"

# A line starting with :: is a workflow command even in a log or a posted
# comment; neutralize it instead of trusting the destination to escape it.
_WORKFLOW_COMMAND = re.compile(r"^::", re.MULTILINE)


def redact(text: str) -> str:
    """``text`` with credential-shaped strings replaced and command lines defused.

    Each pattern is matched twice, and every span either match covers is
    withheld, overlapping or adjacent spans as one. It is matched on the
    original text, so a wide earlier match cannot hide a narrower one: a
    footerless key's base64 run takes in the scheme of a URL on the next line
    ('postgresql+psycopg2://') and stops at ':', after which the URL rule would
    miss the password. It is also matched in turn, on the text with the earlier
    matches masked, as the patterns always ran: an Azure key's value run takes
    in the label of a key glued after it, and the Azure rule finds that second
    key only once a key match has masked the first label. A mask keeps the
    length, so every span indexes the original text.
    """
    spans: list[tuple[int, int]] = []

    def withhold(match: re.Match[str]) -> str:
        spans.append(match.span())
        return "\0" * len(match[0])

    masked = text
    for pattern in _PATTERNS:
        spans.extend(match.span() for match in pattern.finditer(text))
        masked = pattern.sub(withhold, masked)
    pieces: list[str] = []
    end = 0
    for start, stop in sorted(spans):
        if not pieces or start > end:
            pieces += (text[end:start], _REDACTED)
        end = max(end, stop)
    pieces.append(text[end:])
    return _WORKFLOW_COMMAND.sub("\\:\\:", "".join(pieces))
