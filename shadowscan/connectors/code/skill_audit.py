"""Bounded, non-executing review indicators for skill and MCP instruction text.

This is a deliberately narrow lexical audit, not a prompt-injection detector
with a measured error rate. No supplied text, URLs or credential values leave
the helper. Quoted examples and explicit prohibitions are not direct commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from shadowscan.utils.safe_yaml import strict_bounded_safe_load

MAX_TEXT_BYTES = 64 * 1024
MAX_LINE_CHARACTERS = 4096
MAX_FRONTMATTER_BYTES = 8192
MAX_INDICATORS_PER_RULE = 3

_LIMITATIONS = (
    "Static lexical indicators do not establish intent, execution, or safety.",
    "Only direct English instruction forms are inspected; quoted examples, fenced code and YAML "
    "front matter other than name and description are excluded. Links and tools are never "
    "followed or invoked.",
)
# Front matter fields a skill loader places in the agent's context every session.
_AUDITED_FRONT_MATTER = ("name", "description")
_OVERLONG = (
    "Sentences over 4,096 characters were audited only in their first and last 4,096 characters; "
    "the rest of each such sentence was not inspected."
)
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_PREFIX = re.compile(r"^(?:[-+*]\s+|\d{1,6}[.)]\s+|<[^>\n]{1,80}>\s*)*")
# A quoted span runs from an opening mark to the next closing mark on the line:
# `...`, "...", '...' (opened outside a word), “...” or ‘...’.
_QUOTE_OPENER = re.compile(r"[`\"“‘]|(?<!\w)'")
_QUOTE_CLOSER = {"`": "`", '"': '"', "'": "'", "“": "”", "‘": "’"}
# Where an overlong line is split for auditing: after sentence punctuation.
_SENTENCE_BREAK = re.compile(r"(?<=[.!?;])\s+")
_DIRECT = r"(?:^|[.!?;]\s+)(?:please\s+)?"
_OVERRIDE = re.compile(
    _DIRECT + r"(?:ignore|disregard|override)\s+(?:all\s+|the\s+)?"
    r"(?:(?:previous|prior|system|developer|higher-priority)\s+(?:instructions?|prompts?|rules?)"
    r"|(?:safety|security)\s+(?:rules?|polic(?:y|ies)|controls?))\b",
    re.IGNORECASE,
)
_TRANSFER = re.compile(
    _DIRECT + r"(?:send|forward|upload|exfiltrate|reveal|print|disclose|copy)\s+"
    r"(?:(?:the|all|any|your|our|their|raw|full|complete|hidden|stored|saved)\s+){0,4}"
    r"(?:(?:system|developer)\s+prompts?|(?:api|access|auth|session)\s+(?:keys?|tokens?)"
    r"|secrets?|credentials?|passwords?|private\s+keys?|environment\s+variables?)\b",
    re.IGNORECASE,
)
_RULES = (
    ("instruction-override", _OVERRIDE, "Direct instruction to override prior or privileged guidance"),
    ("sensitive-data-transfer", _TRANSFER, "Direct instruction to disclose or transfer sensitive values"),
)


@dataclass(frozen=True)
class InstructionIndicator:
    rule: str
    line: int
    description: str


@dataclass(frozen=True)
class InstructionAudit:
    """``partial``: some text was outside the audited bounds (the middle of an
    overlong line); the audit then never reads as clean, but the caller's
    coverage stays complete. ``incomplete``: the caller reports a coverage gap.
    """

    indicators: tuple[InstructionIndicator, ...]
    incomplete: bool
    limitations: tuple[str, ...]
    partial: bool = False

    def to_metadata(self) -> dict[str, Any]:
        return {
            "method": "bounded-static-instruction-review-v1",
            "status": (
                "incomplete"
                if self.incomplete
                else "indicators-observed"
                if self.indicators
                else "partial"
                if self.partial
                else "no-indicators-observed"
            ),
            "incomplete": self.incomplete,
            "partial": self.partial,
            "indicators": [
                {"rule": hit.rule, "line": hit.line, "description": hit.description}
                for hit in self.indicators
            ],
            "limitations": list(self.limitations),
        }


def audit_skill_text(text: str) -> InstructionAudit:
    """Inspect a bounded snapshot; emit locations and fixed descriptions only.

    The caller reports ``incomplete`` through its connector statistics. Input
    size, malformed front matter and unclosed fences must not certify a clean
    audit. A line over ``MAX_LINE_CHARACTERS`` is audited in its first and
    last ``MAX_LINE_CHARACTERS`` characters and marks the audit ``partial``.
    No evidence weight or agent classification is assigned here.
    """
    limitations = list(_LIMITATIONS)
    incomplete = partial = False
    encoded = text[: MAX_TEXT_BYTES + 1].encode("utf-8", errors="replace")
    if len(text) > MAX_TEXT_BYTES or len(encoded) > MAX_TEXT_BYTES:
        incomplete = True
        limitations.append("Instruction text exceeds the inspection byte limit; only a prefix was inspected.")
        text = encoded[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
    lines = text.splitlines()
    body_start = 0
    indicators: list[InstructionIndicator] = []
    counts: dict[str, int] = {}
    if lines and lines[0].strip() == "---":
        end = next((i for i in range(1, min(len(lines), 129)) if lines[i].strip() == "---"), None)
        if end is None:
            return InstructionAudit((), True, (*limitations, "Unclosed or oversized YAML front matter."))
        header = "\n".join(lines[1:end])
        if len(header.encode("utf-8", errors="replace")) > MAX_FRONTMATTER_BYTES:
            incomplete = True
            limitations.append("YAML front matter exceeds the inspection limit.")
        else:
            try:
                value = strict_bounded_safe_load(header)
                if value is not None and not isinstance(value, dict):
                    raise ValueError("front matter must be a mapping")
            except (ValueError, RecursionError, yaml.YAMLError):
                incomplete = True
                limitations.append("YAML front matter is malformed or exceeds structural limits.")
            else:
                for key in _AUDITED_FRONT_MATTER:
                    field = value.get(key) if isinstance(value, dict) else None
                    if not isinstance(field, str):
                        continue
                    # Report the key's line; a block scalar's own lines do not map back.
                    key_line = next((i + 1 for i in range(1, end) if lines[i].startswith(f"{key}:")), 1)
                    for field_line in field.splitlines():
                        partial |= _audit_text_line(field_line, key_line, indicators, counts)
        body_start = end + 1

    fence: tuple[str, int] | None = None
    for line_number, raw_line in enumerate(lines[body_start:], body_start + 1):
        line = raw_line.strip()
        if line.startswith(">") or raw_line.startswith(("    ", "\t")):
            continue
        if line.startswith(("```", "~~~")):
            marker = line[0]
            count = len(line) - len(line.lstrip(marker))
            if fence is None:
                fence = marker, count
            elif marker == fence[0] and count >= fence[1] and not line[count:].strip():
                fence = None
            continue
        if fence is not None:
            continue
        partial |= _audit_text_line(raw_line, line_number, indicators, counts)
    if partial:
        limitations.append(_OVERLONG)
    if fence is not None:
        incomplete = True
        limitations.append("Unclosed Markdown fence; its remaining content was excluded.")
    if any(count == MAX_INDICATORS_PER_RULE for count in counts.values()):
        limitations.append("At most three locations are retained for each instruction rule.")
    return InstructionAudit(tuple(indicators), incomplete, tuple(limitations), partial)


def _strip_quoted(line: str) -> str:
    """Replace each quoted span of one line with a space, in linear time.

    A span runs from an opening mark to the next closing mark: `...`, "...",
    '...' opened outside a word, “...” or ‘...’; an opener without a closer
    after it is left as text. The equivalent regex alternation retries every
    unmatched opener against the rest of the line, which is quadratic for a
    long run of “ without ”. A closing mark missing after one opener is
    missing after every later one, so each kind is searched to the end of
    the line at most once.
    """
    parts: list[str] = []
    position = 0
    missing: set[str] = set()
    for match in _QUOTE_OPENER.finditer(line):
        start = match.start()
        closer = _QUOTE_CLOSER[match.group()]
        if start < position or closer in missing:
            continue
        end = line.find(closer, start + 1)
        if end < 0:
            missing.add(closer)
            continue
        parts.append(line[position:start])
        parts.append(" ")
        position = end + 1
    parts.append(line[position:])
    return "".join(parts)


def _audit_text_line(
    raw_line: str, line_number: int, indicators: list[InstructionIndicator], counts: dict[str, int]
) -> bool:
    """Audit one line; return whether part of it was outside the audited bounds.

    A line up to ``MAX_LINE_CHARACTERS`` is audited whole. A longer line is
    normalized once (quoted spans and invisible characters removed, both in
    linear time) and audited sentence by sentence: a rule matches only at
    the start of the line or after sentence punctuation and whitespace, and
    no rule body contains that punctuation, so no match spans two sentences.
    Auditing only the two ends of the line let an instruction in its middle
    pass as a clean, complete scan. Only a single sentence over
    ``MAX_LINE_CHARACTERS`` is audited in its first and last
    ``MAX_LINE_CHARACTERS`` characters, which marks the audit partial.
    """
    line = raw_line.strip()
    obfuscated = _INVISIBLE.search(line) is not None
    normalized = _PREFIX.sub("", _INVISIBLE.sub("", _strip_quoted(line))).strip()
    found: set[str] = set()
    if len(raw_line) <= MAX_LINE_CHARACTERS:
        _audit_line(normalized, obfuscated, line_number, found, indicators, counts)
        return False
    partial = False
    for sentence in _SENTENCE_BREAK.split(normalized):
        if len(sentence) > MAX_LINE_CHARACTERS:
            partial = True
            pieces = [sentence[:MAX_LINE_CHARACTERS], sentence[-MAX_LINE_CHARACTERS:].strip()]
        else:
            pieces = [sentence]
        for piece in pieces:
            _audit_line(piece, obfuscated, line_number, found, indicators, counts)
    return partial


def _audit_line(
    normalized: str,
    obfuscated: bool,
    line_number: int,
    found: set[str],
    indicators: list[InstructionIndicator],
    counts: dict[str, int],
) -> None:
    """Apply the instruction rules to one normalized line (or sentence of one).

    ``found`` holds the rules already recorded for this line, so the
    sentences of an overlong line report a rule once. ``obfuscated``: the
    line held invisible characters before they were removed.
    """
    hit = False
    for rule, pattern, description in _RULES:
        if pattern.search(normalized):
            hit = True
            if rule not in found and counts.get(rule, 0) < MAX_INDICATORS_PER_RULE:
                indicators.append(InstructionIndicator(rule, line_number, description))
                counts[rule] = counts.get(rule, 0) + 1
            found.add(rule)
    if hit and obfuscated and not counts.get("obfuscated-instruction"):
        indicators.append(
            InstructionIndicator(
                "obfuscated-instruction", line_number, "Invisible controls occur in a direct instruction"
            )
        )
        counts["obfuscated-instruction"] = 1
