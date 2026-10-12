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
        r"(?:(?:(?:\r?\n|(?:\\r)?\\n)(?:[ \t]*+>)*+[ \t]*+)?"
        r"(?:(?:(?:\r?\n|(?:\\r)?\\n)(?:[ \t]*+>)*+[ \t]*+|[ \t]++)[A-Za-z0-9+/=]{16,})+)?)"
    ),
    re.compile(r"(?i:\b(?:Account|SharedAccess)Key)\s*=\s*[A-Za-z0-9+/]{40,}={0,2}"),
    re.compile(
        r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://"
        r"[^\s/:@'\"<>]+:[^\s/@'\"<>]+@[^\s/'\"<>]"
    ),
)

_REDACTED = "[redacted]"

# The private key rule as the gate ran it before it read footerless keys quoted on one
# line, in blockquotes or after escaped CRLF breaks (see ``redact``): each run of 16 or
# more base64 characters on a line of its own, and then after real or escaped line breaks
# or spaces. Its blank runs are possessive, which keeps the scan linear.
_EARLIER_KEY_RULES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"|(?:\r?\n[ \t]*(?:Proc-Type|DEK-Info):[^\r\n]*)*"
        r"(?:(?:\r?\n[ \t]*)?(?:\r?\n[ \t]*[A-Za-z0-9+/=]{16,})+)?)"
    ),
    re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"|(?:\r?\n[ \t]*(?:Proc-Type|DEK-Info):[^\r\n]*)*"
        r"(?:(?:(?:\r?\n|\\n)[ \t]*+)?(?:(?:(?:\r?\n|\\n)[ \t]*+|[ \t]++)[A-Za-z0-9+/=]{16,})+)?)"
    ),
)
_KEY_RULE = next(index for index, pattern in enumerate(_PATTERNS) if pattern.pattern.startswith("-----BEGIN"))
# The rule sets matched in turn: the current one, and each with an earlier key rule.
_TURN_RULES: tuple[tuple[re.Pattern[str], ...], ...] = (
    _PATTERNS,
    *(_PATTERNS[:_KEY_RULE] + (rule,) + _PATTERNS[_KEY_RULE + 1 :] for rule in _EARLIER_KEY_RULES),
)

# A line starting with :: is a workflow command even in a log or a posted
# comment; neutralize it instead of trusting the destination to escape it.
_WORKFLOW_COMMAND = re.compile(r"^::", re.MULTILINE)


def redact(text: str) -> str:
    """``text`` with credential-shaped strings replaced and command lines defused.

    Every span any of these readings matches is withheld, overlapping or
    adjacent spans as one. Each pattern is matched on the original text, so a
    wide earlier match cannot hide a narrower one: a footerless key's base64
    run takes in the scheme of a URL on the next line ('postgresql+psycopg2://')
    and stops at ':', after which the URL rule would miss the password. The
    patterns are also matched in turn, as they always ran, on the text with
    each earlier match replaced by the marker: an Azure key's value run takes
    in the label of a key glued after it, and the Azure rule finds that second
    key only once a key match has replaced the first label; a long token
    between a private key's header and its footer shrinks to the marker, which
    brings the footer within the key rule's bounded search; and a URL whose
    password holds an Azure key matches once that key is replaced. They run
    in turn with the current key rule and with each earlier one (see
    ``_EARLIER_KEY_RULES``), whose narrower match left a URL's scheme for the
    URL rule, and each set again until it matches nothing more, as repeated
    redaction would (a URL in a URL in a password matches only then). Each
    character of the text matched in turn maps back to the original span it
    stands for, so every span indexes the original text.
    """
    spans = [match.span() for pattern in _PATTERNS for match in pattern.finditer(text)]
    for rules in _TURN_RULES:
        spans += _spans_in_turn(text, rules)
    pieces: list[str] = []
    end = 0
    for start, stop in sorted(spans):
        if not pieces or start > end:
            pieces += (text[end:start], _REDACTED)
        end = max(end, stop)
    pieces.append(text[end:])
    return _WORKFLOW_COMMAND.sub("\\:\\:", "".join(pieces))


# Sweeps of a rule set in turn before redact() gives up and withholds the whole text.
_MAX_SWEEPS = 32


def _spans_in_turn(text: str, rules: tuple[re.Pattern[str], ...]) -> list[tuple[int, int]]:
    """The spans of ``text`` that ``rules`` match in turn, each match replaced before the next rule.

    The rules sweep the text again until a sweep matches nothing. Every match
    replaces text no marker holds, so the sweeps end; a text still matching
    after ``_MAX_SWEEPS`` sweeps is withheld whole.
    """
    spans: list[tuple[int, int]] = []
    current = text
    origin = [(index, index + 1) for index in range(len(text))]
    for _ in range(_MAX_SWEEPS):
        current, origin, found = _sweep(current, origin, rules)
        if not found:
            return spans
        spans += found
    return [(0, len(text))]


def _sweep(
    current: str, origin: list[tuple[int, int]], rules: tuple[re.Pattern[str], ...]
) -> tuple[str, list[tuple[int, int]], list[tuple[int, int]]]:
    """One sweep of ``rules`` in turn: the text after it, its origin map, and the original spans matched."""
    spans: list[tuple[int, int]] = []
    for pattern in rules:
        pieces: list[str] = []
        mapped: list[tuple[int, int]] = []
        end = 0
        for match in pattern.finditer(current):
            start, stop = match.span()
            if start == stop:
                continue
            # The map is ordered, so a match covers its first character's span to its last's.
            covered = (origin[start][0], origin[stop - 1][1])
            spans.append(covered)
            pieces += (current[end:start], _REDACTED)
            mapped += origin[end:start]
            mapped += [covered] * len(_REDACTED)
            end = stop
        if pieces:
            pieces.append(current[end:])
            mapped += origin[end:]
            current, origin = "".join(pieces), mapped
    return current, origin, spans
