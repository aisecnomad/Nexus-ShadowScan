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
MAX_FRONTMATTER_LINES = 128
MAX_INDICATORS_PER_RULE = 3

_LIMITATIONS = (
    "Static lexical indicators do not establish intent, execution, or safety.",
    "Only direct English instruction forms are inspected, in body text and in YAML front matter "
    "values; quoted examples and fenced code are excluded. Links and tools are never followed or "
    "invoked.",
)
_OVERLONG_LINE = "Overlong instruction lines were not inspected."
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_PREFIX = re.compile(r"^(?:[-+*]\s+|\d{1,6}[.)]\s+|<[^>\n]{1,80}>\s*)*")
_QUOTED = re.compile(r"`[^`\n]*`|\"[^\"\n]*\"|(?<!\w)'[^'\n]*'|“[^”\n]*”|‘[^’\n]*’")
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
# YAML front matter is read line by line so that an indicator keeps its line number. A key,
# a list marker and the quotes around a whole scalar are syntax, not a quoted example; a
# block-scalar indicator (``description: |``) has its value on the indented lines below.
_FRONT_MATTER_KEY = re.compile(r"^[A-Za-z_][\w.-]*\s*:(?:\s|$)")
_FRONT_MATTER_SYNTAX = re.compile(r"^(?:[-+*]\s+)*(?:[A-Za-z_][\w.-]*\s*:\s*)?")
_BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?\d?|\d?[+-]?)$")
_WHOLE_SCALAR_QUOTED = re.compile(r"^(?:\"(.*)\"|'(.*)')$")


@dataclass(frozen=True)
class InstructionIndicator:
    rule: str
    line: int
    description: str


@dataclass(frozen=True)
class InstructionAudit:
    indicators: tuple[InstructionIndicator, ...]
    incomplete: bool
    limitations: tuple[str, ...]

    def to_metadata(self) -> dict[str, Any]:
        return {
            "method": "bounded-static-instruction-review-v1",
            "status": (
                "incomplete"
                if self.incomplete
                else "indicators-observed"
                if self.indicators
                else "no-indicators-observed"
            ),
            "incomplete": self.incomplete,
            "indicators": [
                {"rule": hit.rule, "line": hit.line, "description": hit.description}
                for hit in self.indicators
            ],
            "limitations": list(self.limitations),
        }


def _opens_front_matter(lines: list[str]) -> bool:
    """Whether the text under a ``---`` opener starts like YAML front matter: with a ``key:`` line.

    A ``---`` followed by prose or a heading is a Markdown thematic break, not an unclosed header.
    """
    for line in lines:
        if line.strip():
            return bool(_FRONT_MATTER_KEY.match(line.strip()))
    return False


def _normalize(value: str) -> str:
    """Drop quoted examples, invisible controls and list, number or tag prefixes."""
    return _PREFIX.sub("", _INVISIBLE.sub("", _QUOTED.sub(" ", value))).strip()


def _front_matter_value(line: str) -> str | None:
    """The scalar text a front matter line carries, or None when the line holds no value."""
    if not line or line.startswith("#"):
        return None
    value = _FRONT_MATTER_SYNTAX.sub("", line)
    if not value or _BLOCK_SCALAR.match(value):
        return None
    quoted = _WHOLE_SCALAR_QUOTED.match(value)
    if quoted:
        value = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
    return value


def audit_skill_text(text: str) -> InstructionAudit:
    """Inspect a bounded snapshot; emit locations and fixed descriptions only.

    The caller reports ``incomplete`` through its connector statistics. Input
    size, malformed front matter and unclosed fences must not certify a clean
    audit. An overlong line is skipped by the sentence rules, so it is recorded
    as a limitation and marks the audit incomplete while every other line is
    still inspected; a ``---`` that opens no front matter is body text.
    No evidence weight or agent classification is assigned here.
    """
    limitations = list(_LIMITATIONS)
    incomplete = False
    encoded = text[: MAX_TEXT_BYTES + 1].encode("utf-8", errors="replace")
    if len(text) > MAX_TEXT_BYTES or len(encoded) > MAX_TEXT_BYTES:
        incomplete = True
        limitations.append("Instruction text exceeds the inspection byte limit; only a prefix was inspected.")
        text = encoded[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
    lines = text.splitlines()
    body_start = 0
    header_end = 0
    if lines and lines[0].strip() == "---":
        window = min(len(lines), MAX_FRONTMATTER_LINES + 1)
        end = next((i for i in range(1, window) if lines[i].strip() == "---"), None)
        if end is not None:
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
            header_end = end
            body_start = end + 1
        elif _opens_front_matter(lines[1:window]):
            return InstructionAudit((), True, (*limitations, "Unclosed or oversized YAML front matter."))
        # Otherwise the opener is a thematic break and everything after it is body text.

    indicators: list[InstructionIndicator] = []
    counts: dict[str, int] = {}

    def overlong(raw_line: str) -> bool:
        # The sentence rules are skipped on an overlong line to stay bounded; the line is
        # then uninspected here, which is a limit hit and never a clean audit of it.
        nonlocal incomplete
        if len(raw_line) <= MAX_LINE_CHARACTERS:
            return False
        incomplete = True
        if _OVERLONG_LINE not in limitations:
            limitations.append(_OVERLONG_LINE)
        return True

    def inspect(normalized: str, raw_line: str, line_number: int) -> None:
        found = False
        for rule, pattern, description in _RULES:
            if pattern.search(normalized):
                found = True
                if counts.get(rule, 0) < MAX_INDICATORS_PER_RULE:
                    indicators.append(InstructionIndicator(rule, line_number, description))
                    counts[rule] = counts.get(rule, 0) + 1
        if found and _INVISIBLE.search(raw_line) and not counts.get("obfuscated-instruction"):
            indicators.append(
                InstructionIndicator(
                    "obfuscated-instruction", line_number, "Invisible controls occur in a direct instruction"
                )
            )
            counts["obfuscated-instruction"] = 1

    # Front matter values: a description or instruction field can carry an instruction.
    for index in range(1, header_end):
        raw_line = lines[index]
        if overlong(raw_line):
            continue
        value = _front_matter_value(raw_line.strip())
        if value is not None:
            inspect(_normalize(value), raw_line, index + 1)

    fence: tuple[str, int] | None = None
    for line_number, raw_line in enumerate(lines[body_start:], body_start + 1):
        if overlong(raw_line):
            continue
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
        inspect(_normalize(line), line, line_number)
    if fence is not None:
        incomplete = True
        limitations.append("Unclosed Markdown fence; its remaining content was excluded.")
    if any(count == MAX_INDICATORS_PER_RULE for count in counts.values()):
        limitations.append("At most three locations are retained for each instruction rule.")
    return InstructionAudit(tuple(indicators), incomplete, tuple(limitations))
