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
    "front matter are excluded. Links and tools are never followed or invoked.",
)
_OVERLONG = (
    "Lines over 4,096 characters were audited only in their first and last 4,096 characters; "
    "the rest of each such line was not inspected."
)
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
        body_start = end + 1

    indicators: list[InstructionIndicator] = []
    counts: dict[str, int] = {}
    fence: tuple[str, int] | None = None
    for line_number, raw_line in enumerate(lines[body_start:], body_start + 1):
        segments = [raw_line]
        if len(raw_line) > MAX_LINE_CHARACTERS:
            # Bound regex work per line: audit both ends, say the middle was not.
            segments = [raw_line[:MAX_LINE_CHARACTERS], raw_line[-MAX_LINE_CHARACTERS:]]
            if not partial:
                partial = True
                limitations.append(_OVERLONG)
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
        found: set[str] = set()
        for segment in segments:
            _audit_line(segment.strip(), line_number, found, indicators, counts)
    if fence is not None:
        incomplete = True
        limitations.append("Unclosed Markdown fence; its remaining content was excluded.")
    if any(count == MAX_INDICATORS_PER_RULE for count in counts.values()):
        limitations.append("At most three locations are retained for each instruction rule.")
    return InstructionAudit(tuple(indicators), incomplete, tuple(limitations), partial)


def _audit_line(
    line: str,
    line_number: int,
    found: set[str],
    indicators: list[InstructionIndicator],
    counts: dict[str, int],
) -> None:
    """Apply the instruction rules to one stripped line (or segment of one).

    ``found`` holds the rules already recorded for this line, so the two ends
    of an overlong line report a rule once.
    """
    normalized = _INVISIBLE.sub("", _QUOTED.sub(" ", line))
    normalized = _PREFIX.sub("", normalized).strip()
    hit = False
    for rule, pattern, description in _RULES:
        if pattern.search(normalized):
            hit = True
            if rule not in found and counts.get(rule, 0) < MAX_INDICATORS_PER_RULE:
                indicators.append(InstructionIndicator(rule, line_number, description))
                counts[rule] = counts.get(rule, 0) + 1
            found.add(rule)
    if hit and _INVISIBLE.search(line) and not counts.get("obfuscated-instruction"):
        indicators.append(
            InstructionIndicator(
                "obfuscated-instruction", line_number, "Invisible controls occur in a direct instruction"
            )
        )
        counts["obfuscated-instruction"] = 1
