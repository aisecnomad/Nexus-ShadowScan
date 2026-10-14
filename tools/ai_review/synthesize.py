"""Orchestrator/synthesizer for the AI Review Gate.

Runs the deterministic half of the multi-agent review: it reads the reviewer
agents' finding artifacts, validates them against the schema, deduplicates
them against scanner evidence and each other, redacts them, and renders the
single consolidated GitHub Review plus the gate decision that the
ai-review-gate workflow posts.

The workflow runs the base-ref copy of this module, never the pull request's.
Every input (finding files, diff list, labels, scanner fingerprints) is
untrusted. The gate fails closed:

- findings directory missing or unreadable  -> failure (bypass_unavailable)
- any finding file that is not valid schema -> failure (malformed_findings)
- a finding that names a file not in the diff -> failure (stale_findings)
- ``ai-review: blocked`` label on the PR     -> failure (blocked_label)
- high-risk diff with zero valid findings    -> failure (insufficient_evidence)
- any critical/high finding                  -> failure (blocking_findings)

Otherwise the gate is advisory (``neutral``). The review is always posted as
COMMENT: the check run carries the verdict, so a bot that never approves
never leaves a sticky REQUEST_CHANGES behind. This script never has merge
authority; branch protection and human reviewers decide.

Exit codes: 0 gate advisory, 1 gate fails, 2 usage error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from tools.ai_review.sanitize import redact
from tools.ai_review.schema import BLOCKING_SEVERITIES, MAX_FINDINGS_PER_FILE, Finding, parse_finding

MAX_INLINE_COMMENTS = 50

# Finding files per directory. The same bound applies to one specialist's
# directory and to the aggregate the publisher assembles from all of them, so
# evidence that validates always synthesizes.
MAX_FINDINGS_FILES = 20

# GitHub rejects review bodies over 65,536 characters. The synthesizer stays
# under that less a reserve for what the publisher appends afterwards: the
# restated decision header and its fixed preflight and label notices.
MAX_REVIEW_BODY = 65_536
PUBLISHER_RESERVE = 1_024
_FOOTER_RESERVE = 256

# The review never carries the verdict. A bot that never approves must not
# leave a sticky REQUEST_CHANGES; the check run's conclusion decides.
REVIEW_EVENT = "COMMENT"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

BLOCKED_LABEL = "ai-review: blocked"
HIGH_RISK_LABEL = "ai-review: high-risk"

_TRAILER = (
    "_AI-assisted review is advisory evidence for the human gate. "
    "It is not independent human review, and branch protection — not this review — decides the merge._"
)


class GateInputError(Exception):
    """A required input is missing or unusable; never a passing gate."""


def _open_directory(path: Path) -> int:
    """A descriptor for the directory at ``path``; no component may be a symlink."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.absolute().parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
    except OSError:
        os.close(fd)
        raise
    return fd


def read_input(path: Path, limit: int = 1_000_000) -> str:
    """Read bounded regular inputs without following any symlink component."""
    import stat

    try:
        absolute = path.absolute()
        fd = _open_directory(absolute.parent)
        try:
            child = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        finally:
            os.close(fd)
        with os.fdopen(child, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GateInputError("input is not a regular file")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise GateInputError("input size limit exceeded")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateInputError("input unavailable") from exc


def load_json(text: str | bytes) -> Any:
    """Decode untrusted JSON; nesting too deep for the decoder is malformed input, not a crash.

    ``json.loads`` raises RecursionError, a RuntimeError, for a deeply nested array or object.
    Every caller handles ValueError as malformed evidence, so the gate fails closed with a
    review instead of dying with the check left in progress.
    """
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc


def _read_diff_files(path: Path) -> set[str]:
    try:
        text = read_input(path)
    except GateInputError as exc:
        raise GateInputError("diff file list unreadable") from exc
    from tools.ai_review.schema import _path

    if any(_path(line) != line for line in text.splitlines()):
        raise GateInputError("diff file list malformed")
    return {line.strip() for line in text.splitlines() if line.strip()}


def _read_scanner_fingerprints(path: Path | None) -> set[str]:
    """Fingerprints of findings a scanner (CodeQL, secret scanning, Dependabot)
    already reported; agent findings carrying one are deduplicated onto it."""
    if path is None:
        return set()
    try:
        data = load_json(read_input(path))
    except (GateInputError, ValueError) as exc:
        raise GateInputError("scanner fingerprint list unreadable or not JSON") from exc
    if not isinstance(data, list) or any(
        not isinstance(item, str) or not item.strip() or len(item) > 200 for item in data
    ):
        raise GateInputError("scanner fingerprint list must be a JSON list of strings")
    return set(data)


def findings_files(directory: Path, limit: int = MAX_FINDINGS_FILES) -> list[Path]:
    """The ``*.json`` entries of ``directory``, sorted, at most ``limit`` of them.

    The directory comes from the pull request. It is enumerated through a
    descriptor opened without following any symlink, and the limit applies
    while iterating: a symlink anywhere in its path is malformed evidence to
    reject, not a directory to list, because following it would enumerate an
    arbitrary runner directory from the trusted job.
    """
    try:
        fd = _open_directory(directory)
    except OSError as exc:
        raise GateInputError("findings directory missing, symlinked or not a directory") from exc
    names: list[str] = []
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                if not entry.name.endswith(".json"):
                    continue
                if len(names) >= limit:
                    raise GateInputError("findings artifact limit exceeded")
                names.append(entry.name)
    except OSError as exc:
        raise GateInputError("findings directory unreadable") from exc
    finally:
        os.close(fd)
    if not names:
        raise GateInputError("findings directory empty")
    return [directory / name for name in sorted(names)]


def read_findings(files: list[Path]) -> tuple[list[Finding], int]:
    """All valid findings in ``files`` and the count of invalid files.

    A file that is not a regular file, has invalid JSON, no valid findings,
    or more than MAX_FINDINGS_PER_FILE entries counts as invalid: a reviewer
    that cannot produce the schema produces noise, and the gate fails closed
    on noise.
    """
    findings: list[Finding] = []
    invalid_files = 0
    for file in files:
        try:
            data = load_json(read_input(file))
        except (GateInputError, ValueError):
            invalid_files += 1
            continue
        entries = data if isinstance(data, list) else [data]
        if not entries or len(entries) > MAX_FINDINGS_PER_FILE:
            invalid_files += 1
            continue
        parsed = [finding for finding in (parse_finding(entry) for entry in entries) if finding]
        if len(parsed) != len(entries):
            invalid_files += 1
        findings.extend(parsed)
    return findings, invalid_files


def load_findings(directory: Path, limit: int = MAX_FINDINGS_FILES) -> tuple[list[Finding], int]:
    """All valid findings under ``directory`` and the count of invalid files."""
    return read_findings(findings_files(directory, limit))


# Author-supplied evidence can block a change but never vouch for one.
ADVISORY = "neutral"


def decide(
    findings: list[Finding],
    *,
    labels: set[str],
    high_risk: bool,
    invalid_files: int,
    diff_files: set[str],
) -> tuple[str, str]:
    """The gate verdict as ``(conclusion, reason)`` for the check run.

    ``conclusion`` is neutral or failure. Fail-closed ordering: external block
    first, then integrity failures, then content. The review event is always
    REVIEW_EVENT and never part of the verdict.

    The evidence is committed by the pull request's author, so its absence of
    blocking findings proves nothing: the gate can block a change but never
    pass one, and its best outcome is ``neutral`` (advisory), never
    ``success``.
    """
    if BLOCKED_LABEL in labels:
        return "failure", "blocked_label"
    if invalid_files:
        return "failure", "malformed_findings"
    stale = sorted(
        {finding.path for finding in findings if finding.path is not None and finding.path not in diff_files}
    )
    if stale:
        return "failure", "stale_findings"
    if high_risk and not findings:
        return "failure", "insufficient_evidence"
    if any(finding.severity in BLOCKING_SEVERITIES for finding in findings):
        return "failure", "blocking_findings"
    return ADVISORY, "advisory_only"


def dedupe(findings: list[Finding], scanner_fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Unique findings by identity; scanner-reported and duplicate ones drop out."""
    seen: set[str] = set(scanner_fingerprints)
    unique: list[Finding] = []
    dropped = 0
    for finding in sorted(findings, key=lambda finding: SEVERITY_RANK[finding.severity]):
        if finding.identity in seen:
            dropped += 1
            continue
        seen.add(finding.identity)
        unique.append(finding)
    unique.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.agent, f.path or "", f.line or 0, f.title))
    return unique, dropped


def _location(finding: Finding) -> str:
    return f"`{finding.path}:{finding.line}`" if finding.path is not None and finding.line is not None else ""


def _comment_body(finding: Finding) -> str:
    header = f"**[{finding.severity.upper()}] {finding.title}**  — _{finding.agent} reviewer_"
    refs = "  ".join(
        part
        for part in (
            _location(finding),
            f"`{finding.cwe}`" if finding.cwe else "",
            f"`{finding.owasp}`" if finding.owasp else "",
            f"confidence: {finding.confidence}" if finding.confidence else "",
        )
        if part
    )
    return redact("\n\n".join(part for part in (header, refs, finding.body) if part))


def _summary_line(finding: Finding) -> str:
    """One bounded line for a finding whose body does not fit the review."""
    where = f" — {_location(finding)}" if finding.path is not None else ""
    return redact(f"- **[{finding.severity.upper()}]** {finding.title}{where} — _{finding.agent} reviewer_")


def _fit(findings: list[Finding], budget: int) -> tuple[list[str], list[str], int]:
    """``findings`` rendered within ``budget`` characters, in the order given.

    Full entries while they fit; from the first that does not, one summary
    line per finding (severity, title, location); and when even those run
    out, a count of the rest. Returns ``(entries, summary_lines, unlisted)``.
    """
    entries: list[str] = []
    listed: list[str] = []
    used = 0
    unlisted = 0
    for finding in findings:
        if not listed and not unlisted:
            entry = _comment_body(finding)
            if used + len(entry) + 2 <= budget:
                entries.append(entry)
                used += len(entry) + 2
                continue
        if not unlisted:
            line = _summary_line(finding)
            if used + len(line) + 1 <= budget:
                listed.append(line)
                used += len(line) + 1
                continue
        unlisted += 1
    return entries, listed, unlisted


def decision_line(conclusion: str, reason: str, high_risk: bool) -> str:
    """The review's header line stating the check conclusion and its reason."""
    return f"**Decision:** `{conclusion}` — **reason:** `{reason}`" + (
        " — high-risk paths in diff." if high_risk else ""
    )


def restate(body: str, *, conclusion: str, reason: str, high_risk: bool) -> str:
    """``body`` with its decision header replaced, so the review and the check agree.

    Only the first header line is rewritten: it precedes every finding, so
    untrusted finding text that imitates one is left as it is.
    """
    lines = body.split("\n")
    for index, line in enumerate(lines):
        if line.startswith("**Decision:**"):
            lines[index] = decision_line(conclusion, reason, high_risk)
            return "\n".join(lines)
    return "\n".join([decision_line(conclusion, reason, high_risk), *lines])


def render(
    findings: list[Finding],
    *,
    conclusion: str,
    reason: str,
    high_risk: bool,
    invalid_files: int,
    duplicates: int,
) -> tuple[str, list[dict[str, object]]]:
    """The consolidated review body and at most MAX_INLINE_COMMENTS comments.

    Every finding is in the body, in severity order and with its location
    when it has one, within MAX_REVIEW_BODY less PUBLISHER_RESERVE. The
    comments list the located findings as inline candidates; the publisher
    does not post them inline, since a file list does not prove a line is
    commentable.
    """
    inline = [f for f in findings if f.path is not None and f.line is not None][:MAX_INLINE_COMMENTS]

    counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_RANK}
    lines = [
        "## AI Review Gate",
        "",
        decision_line(conclusion, reason, high_risk),
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {severity} | {counts[severity]} |" for severity in SEVERITY_RANK]
    lines.append("")
    lines.append(
        f"{len(findings)} unique finding(s)"
        f" ({duplicates} duplicate or scanner-reported dropped, {invalid_files} invalid artifact(s))."
    )
    if reason == "advisory_only":
        lines.append("")
        lines.append(
            "> No blocking finding in the evidence. The evidence is committed by this pull "
            "request's author, so this is advisory only: it is not a review or an approval."
        )
    if reason == "insufficient_evidence":
        lines.append("")
        lines.append(
            "> High-risk paths changed and no reviewer produced a finding. "
            "Defaulting to *insufficient evidence for security acceptance* rather than a silent pass."
        )
    if reason == "malformed_findings":
        lines.append("")
        lines.append(
            "> One or more reviewer artifacts were missing, unreadable or off-schema. "
            "The gate fails closed; re-run the reviewers."
        )
    if reason == "stale_findings":
        lines.append("")
        lines.append(
            "> One or more findings named files outside this pull request's diff and were "
            "dropped from this review. Any findings on files the diff does contain are "
            "listed below; the gate fails closed on the stale ones."
        )
    budget = MAX_REVIEW_BODY - PUBLISHER_RESERVE - _FOOTER_RESERVE - len("\n".join(lines)) - len(_TRAILER)
    entries, listed, unlisted = _fit(findings, budget)
    for entry in entries:
        lines.append("")
        lines.append(entry)
    if listed or unlisted:
        lines.append("")
        lines.append(
            f"> Review size limit reached: {len(listed) + unlisted} finding bodies omitted; "
            f"{len(listed)} listed by severity, title and location below and {unlisted} not listed. "
            "The committed evidence holds every finding."
        )
        lines.append("")
        lines.extend(listed)
    lines.append("")
    lines.append(_TRAILER)
    body = redact("\n".join(lines))
    comments: list[dict[str, object]] = [
        {"path": redact(f.path or ""), "line": f.line, "side": "RIGHT", "body": _comment_body(f)}
        for f in inline
    ]
    return body, comments


def main() -> int:
    out_dir = os.environ.get("AI_REVIEW_OUT_DIR")
    findings_dir = os.environ.get("AI_REVIEW_FINDINGS_DIR")
    diff_list = os.environ.get("AI_REVIEW_DIFF_FILES")
    if not out_dir or not findings_dir or not diff_list:
        print(
            "usage: AI_REVIEW_OUT_DIR=.. AI_REVIEW_FINDINGS_DIR=.. AI_REVIEW_DIFF_FILES=.. "
            "python -m tools.ai_review.synthesize",
            file=sys.stderr,
        )
        return 2
    labels = {label.strip() for label in os.environ.get("AI_REVIEW_LABELS", "").split(",") if label.strip()}
    high_risk = os.environ.get("AI_REVIEW_HIGH_RISK", "false").lower() == "true" or HIGH_RISK_LABEL in labels
    scanner_path = os.environ.get("AI_REVIEW_SCANNER_FINGERPRINTS")

    scanner_fingerprints: set[str] = set()
    try:
        diff_files = _read_diff_files(Path(diff_list))
        scanner_fingerprints = _read_scanner_fingerprints(Path(scanner_path) if scanner_path else None)
        raw, invalid_files = load_findings(Path(findings_dir))
    except GateInputError as exc:
        # Missing evidence is a failing gate, not a passing one.
        raw, invalid_files, diff_files = [], 0, set()
        conclusion, reason = "failure", "bypass_unavailable"
        if BLOCKED_LABEL in labels:
            reason = "blocked_label"
        print(f"ai-review-gate: {exc} -> {reason}", file=sys.stderr)
    else:
        conclusion, reason = decide(
            raw,
            labels=labels,
            high_risk=high_risk,
            invalid_files=invalid_files,
            diff_files=diff_files,
        )

    unique, duplicates = dedupe(raw, scanner_fingerprints)
    if reason == "stale_findings":
        # A finding that names a file the diff does not contain is dropped and
        # disclosed by render()'s stale-findings notice, never rendered against
        # that file; the findings on files the diff does contain stay in the
        # review.
        unique = [f for f in unique if f.path is None or f.path in diff_files]
    body, comments = render(
        unique,
        conclusion=conclusion,
        reason=reason,
        high_risk=high_risk,
        invalid_files=invalid_files,
        duplicates=duplicates,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "review-body.md").write_text(body + "\n", encoding="utf-8")
    (out / "review-comments.json").write_text(json.dumps(comments, indent=2) + "\n", encoding="utf-8")
    decision = {
        "event": REVIEW_EVENT,
        "conclusion": conclusion,
        "reason": reason,
        "high_risk": high_risk,
        "findings": len(unique),
        "duplicates_dropped": duplicates,
        "invalid_artifacts": invalid_files,
        "inline_comments": len(comments),
    }
    (out / "decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(f"ai-review-gate: {json.dumps(decision)}")
    return 0 if conclusion == ADVISORY else 1


if __name__ == "__main__":
    raise SystemExit(main())
