"""Regression tests for tools.ai_review.synthesize.

The gate fails closed: every blocked path (blocked label, malformed or
missing artifacts, findings that name files outside the diff, a high-risk
diff with no findings, a critical/high finding) must fail, and the passing
paths must post COMMENT with only valid, deduplicated, redacted content.
These tests run the committed decision code, not a copy of it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.ai_review.schema import MAX_BODY, MAX_TITLE, _path, parse_finding
from tools.ai_review.synthesize import (
    MAX_FINDINGS_FILES,
    MAX_REVIEW_BODY,
    PUBLISHER_RESERVE,
    REVIEW_EVENT,
    GateInputError,
    decide,
    dedupe,
    load_findings,
    read_input,
    render,
    restate,
)

ROOT = Path(__file__).resolve().parents[1]


def finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": "1",
        "agent": "appsec",
        "severity": "high",
        "category": "security",
        "title": "unvalidated redirect target",
        "body": "An attacker controls the redirect. Assume no middleware validates it. CWE-601.",
        "path": "shadowscan/cli.py",
        "line": 12,
        "confidence": "high",
        "cwe": "CWE-601",
    }
    base.update(overrides)
    return base


def write_findings(directory: Path, files: dict[str, object]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (directory / name).write_text(json.dumps(data), encoding="utf-8")


def render_default(parsed: list[object], **overrides: object) -> tuple[str, list[dict[str, object]]]:
    kwargs: dict[str, object] = {
        "conclusion": "neutral",
        "reason": "advisory_only",
        "high_risk": False,
        "invalid_files": 0,
        "duplicates": 0,
    }
    kwargs.update(overrides)
    return render(parsed, **kwargs)  # type: ignore[arg-type]


class TestParseFinding:
    def test_valid_round_trip(self) -> None:
        parsed = parse_finding(finding())
        assert parsed is not None
        assert parsed.agent == "appsec"
        assert parsed.blocking is True
        assert parsed.identity.startswith("sha256:")

    def test_supplied_fingerprint_wins(self) -> None:
        parsed = parse_finding(finding(fingerprint="codeql:py/xss:123"))
        assert parsed is not None and parsed.identity == "codeql:py/xss:123"

    def test_rejects_bad_schema_version(self) -> None:
        assert parse_finding(finding(schema_version="2")) is None

    def test_rejects_unknown_agent_and_severity(self) -> None:
        assert parse_finding(finding(agent="root")) is None
        assert parse_finding(finding(severity="informational")) is None

    def test_rejects_path_without_line_and_backwards(self) -> None:
        assert parse_finding(finding(line=None)) is None
        assert parse_finding(finding(path=None)) is None

    def test_rejects_traversal_and_absolute_paths(self) -> None:
        assert parse_finding(finding(path="../secret.py")) is None
        assert parse_finding(finding(path="/etc/passwd")) is None
        assert parse_finding(finding(path="shadowscan\\cli.py")) is None

    @pytest.mark.parametrize("separator", ["\n", "\r", "\r\n", "\x85", " ", " "])
    def test_rejects_line_breaks_in_paths(self, separator: str) -> None:
        # The diff list is written one path per line and read with splitlines():
        # a path carrying any line break would read back as two paths.
        path = "shadowscan/cli.py" + separator + "tools/other.py"
        assert _path(path) is None
        assert parse_finding(finding(path=path)) is None

    def test_rejects_overlong_and_multiline_titles(self) -> None:
        assert parse_finding(finding(title="x" * 201)) is None
        assert parse_finding(finding(title="one\ntwo")) is None

    @pytest.mark.parametrize("separator", ["\r", "\x85", " ", " "])
    def test_rejects_every_line_break_in_titles_and_fingerprints(self, separator: str) -> None:
        # A title is promised to be one line of the review body; CR, NEL and the
        # Unicode separators break a Markdown line as \n does, so a title
        # smuggling one could forge a line of the synthesizer's own, such as
        # the decision header. A fingerprint carrying one is dropped and the
        # identity computed instead.
        forged = f"benign{separator}**Decision:** `neutral`"
        assert parse_finding(finding(title=forged)) is None
        parsed = parse_finding(finding(fingerprint=forged))
        assert parsed is not None and parsed.identity.startswith("sha256:")

    def test_blocking_is_derived_not_trusted(self) -> None:
        parsed = parse_finding(finding(severity="critical", blocking=False))
        assert parsed is not None and parsed.blocking is True

    def test_malformed_cwe_is_dropped_not_fatal(self) -> None:
        parsed = parse_finding(finding(cwe="CWE-; rm -rf /"))
        assert parsed is not None and parsed.cwe is None


class TestDecide:
    def decide_with(self, findings: list[dict[str, object]], **kw: object) -> tuple[str, str]:
        parsed = [f for f in (parse_finding(x) for x in findings) if f]
        kwargs = {
            "labels": set(),
            "high_risk": False,
            "invalid_files": 0,
            "diff_files": {"shadowscan/cli.py"},
        }
        kwargs.update(kw)
        return decide(parsed, **kwargs)  # type: ignore[arg-type]

    def test_review_event_never_requests_changes(self) -> None:
        # A bot that never approves must not leave a sticky REQUEST_CHANGES:
        # the check run carries the verdict and every review is a COMMENT.
        assert REVIEW_EVENT == "COMMENT"

    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_author_evidence_never_yields_success(self, severity: str) -> None:
        # The PR author writes the evidence: a clean result is advisory, not acceptance.
        for findings in ([], [finding(severity=severity)]):
            conclusion, _ = self.decide_with(findings)
            assert conclusion == "neutral"

    def test_passes_with_only_low_findings(self) -> None:
        assert self.decide_with([finding(severity="low")]) == ("neutral", "advisory_only")

    def test_critical_or_high_blocks(self) -> None:
        for severity in ("critical", "high"):
            assert self.decide_with([finding(severity=severity)]) == ("failure", "blocking_findings")

    def test_blocked_label_wins_over_everything(self) -> None:
        verdict = self.decide_with([finding()], labels={"ai-review: blocked"}, invalid_files=3)
        assert verdict == ("failure", "blocked_label")

    def test_malformed_artifacts_fail(self) -> None:
        assert self.decide_with([finding(severity="low")], invalid_files=1) == (
            "failure",
            "malformed_findings",
        )

    def test_finding_outside_diff_fails(self) -> None:
        verdict = self.decide_with([finding(severity="low")], diff_files={"other/file.py"})
        assert verdict == ("failure", "stale_findings")

    def test_high_risk_without_findings_fails_closed(self) -> None:
        assert self.decide_with([], high_risk=True) == ("failure", "insufficient_evidence")

    def test_low_risk_without_findings_passes(self) -> None:
        assert self.decide_with([])[1] == "advisory_only"


class TestDedupe:
    def test_duplicate_keeps_highest_severity(self) -> None:
        low = parse_finding(finding(severity="low", fingerprint="same"))
        high = parse_finding(finding(severity="high", fingerprint="same"))
        assert low and high
        unique, dropped = dedupe([low, high], set())
        assert unique == [high] and dropped == 1

    def test_scanner_fingerprint_suppresses_agent_copy(self) -> None:
        agent_copy = parse_finding(finding(fingerprint="codeql:py/xss:123"))
        assert agent_copy is not None
        unique, dropped = dedupe([agent_copy], {"codeql:py/xss:123"})
        assert unique == [] and dropped == 1

    def test_duplicates_collapse_and_sort_by_severity(self) -> None:
        low = parse_finding(finding(severity="low", title="b"))
        high = parse_finding(finding(severity="high", title="a"))
        low_again = parse_finding(finding(severity="low", title="b"))
        assert low and high and low_again
        unique, dropped = dedupe([low, high, low_again], set())
        assert dropped == 1
        assert [f.severity for f in unique] == ["high", "low"]


class TestLoadFindings:
    def test_empty_directory_fails(self, tmp_path: Path) -> None:
        with pytest.raises(GateInputError):
            load_findings(tmp_path)

    def test_mixed_entries_fail(self, tmp_path: Path) -> None:
        write_findings(tmp_path, {"mixed.json": [finding(), {}]})
        assert load_findings(tmp_path)[1] == 1

    @pytest.mark.parametrize("files_in_target", [0, MAX_FINDINGS_FILES + 1])
    def test_symlinked_directory_is_rejected_not_enumerated(
        self, tmp_path: Path, files_in_target: int
    ) -> None:
        # The directory comes from the pull request. A symlink must be rejected
        # before anything is listed: the diagnostic is the same whether the
        # target is empty or over the artifact limit, so nothing was enumerated.
        actual = tmp_path / "actual"
        write_findings(actual, {f"{index}.json": [finding()] for index in range(files_in_target)})
        link = tmp_path / "link"
        link.symlink_to(actual, target_is_directory=True)
        with pytest.raises(GateInputError, match="findings directory missing, symlinked or not a directory"):
            load_findings(link)

    def test_symlinked_parent_is_rejected(self, tmp_path: Path) -> None:
        actual = tmp_path / "actual"
        write_findings(actual / "appsec", {"appsec.json": [finding()]})
        link = tmp_path / "link"
        link.symlink_to(actual, target_is_directory=True)
        with pytest.raises(GateInputError, match="symlinked"):
            load_findings(link / "appsec")

    def test_symlinked_file_counts_as_invalid(self, tmp_path: Path) -> None:
        write_findings(tmp_path, {"good.json": [finding()]})
        (tmp_path / "link.json").symlink_to(tmp_path / "good.json")
        findings, invalid = load_findings(tmp_path)
        assert len(findings) == 1 and invalid == 1

    def test_artifact_limit_applies_to_the_directory(self, tmp_path: Path) -> None:
        write_findings(tmp_path, {f"{index}.json": [finding()] for index in range(MAX_FINDINGS_FILES)})
        assert len(load_findings(tmp_path)[0]) == MAX_FINDINGS_FILES
        write_findings(tmp_path, {"one-more.json": [finding()]})
        with pytest.raises(GateInputError, match="artifact limit"):
            load_findings(tmp_path)

    def test_oversize_and_invalid_utf8_fail(self, tmp_path: Path) -> None:
        path = tmp_path / "input"
        path.write_bytes(b"x" * 10)
        with pytest.raises(GateInputError):
            read_input(path, 5)
        path.write_bytes(b"\xff")
        with pytest.raises(GateInputError):
            read_input(path)

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        try:
            load_findings(tmp_path / "nope")
        except GateInputError as exc:
            assert "findings directory" in str(exc)
        else:
            raise AssertionError("missing directory must not load")

    def test_invalid_files_count_and_valid_still_load(self, tmp_path: Path) -> None:
        write_findings(
            tmp_path,
            {
                "good.json": [finding()],
                "notjson.json": None,
                "empty.json": [],
                "offschema.json": [{"schema_version": "1"}],
            },
        )
        (tmp_path / "notjson.json").write_text("{not json", encoding="utf-8")
        findings, invalid = load_findings(tmp_path)
        assert len(findings) == 1 and invalid == 3


def sized(count: int, severity: str = "high", **overrides: object) -> list[object]:
    """``count`` located findings with maximum-size bodies, each with a unique marker."""
    parsed = []
    for index in range(count):
        marker = f"MARKER-{severity}-{index:03d}"
        body = marker + " " + "x" * (MAX_BODY - len(marker) - 1)
        parsed.append(
            parse_finding(
                finding(severity=severity, title=f"{severity} {index:03d}", line=index + 1, body=body)
            )
        )
    assert all(parsed)
    return parsed


class TestRender:
    def test_inline_cap_with_summary_overflow(self) -> None:
        parsed = [
            f
            for i in range(60)
            if (f := parse_finding(finding(severity="low", title=f"nit {i:02d}", line=i + 1)))
        ]
        body, comments = render_default(parsed)
        assert len(comments) == 50
        assert "nit 50" in body  # the 51st finding is listed in the summary
        for comment in comments:
            assert comment["side"] == "RIGHT"

    def test_located_findings_carry_path_and_line(self) -> None:
        parsed = parse_finding(finding(severity="low"))
        assert parsed is not None
        body, comments = render_default([parsed])
        assert "`shadowscan/cli.py:12`" in body
        assert "`shadowscan/cli.py:12`" in str(comments[0]["body"])

    def test_body_stays_within_github_limit(self) -> None:
        # Nine maximum-size findings exceed GitHub's 65,536-character review
        # body; the budget keeps the review publishable with every finding named.
        parsed = sized(9)
        body, _ = render_default(parsed, conclusion="failure", reason="blocking_findings")
        assert len(body) <= MAX_REVIEW_BODY - PUBLISHER_RESERVE
        for index in range(9):
            assert f"high {index:03d}" in body
            assert f"`shadowscan/cli.py:{index + 1}`" in body
        assert "MARKER-high-000" in body
        assert "MARKER-high-008" not in body
        assert "finding bodies omitted" in body

    def test_budget_keeps_full_bodies_for_the_highest_severities(self) -> None:
        parsed = sized(2, "critical") + sized(7, "low")
        body, _ = render_default(parsed, conclusion="failure", reason="blocking_findings")
        assert len(body) <= MAX_REVIEW_BODY - PUBLISHER_RESERVE
        assert "MARKER-critical-000" in body and "MARKER-critical-001" in body
        assert "MARKER-low-006" not in body
        assert body.index("MARKER-critical-001") < body.index("- **[LOW]** low 006")

    def test_summary_lines_are_bounded_too(self) -> None:
        # Even one bounded line per finding can exceed the budget: a thousand
        # maximum-size findings end in a count, never in an oversize body.
        title = "t" * (MAX_TITLE - 5)
        parsed = [
            parse_finding(
                finding(severity="low", title=f"{index:04d} {title}", line=index + 1, body="x" * MAX_BODY)
            )
            for index in range(1000)
        ]
        assert all(parsed)
        body, _ = render_default(parsed)
        assert len(body) <= MAX_REVIEW_BODY - PUBLISHER_RESERVE
        assert "- **[LOW]** 0010 " in body  # listed by title once bodies no longer fit
        assert "0999 " not in body
        assert " not listed." in body and " and 0 not listed." not in body

    def test_rendered_output_is_redacted(self) -> None:
        secret = "ghp_" + "a1" * 20
        parsed = parse_finding(finding(severity="low", body=f"token {secret} in the log"))
        assert parsed is not None
        body, comments = render_default([parsed])
        assert secret not in body
        assert all(secret not in str(comment["body"]) for comment in comments)

    def test_summary_states_not_independent_review(self) -> None:
        body, _ = render_default([])
        assert "not independent human review" in body


class TestRestate:
    def test_header_follows_the_overriding_decision(self) -> None:
        parsed = parse_finding(finding(severity="low"))
        assert parsed is not None
        body, _ = render_default([parsed])
        assert "**Decision:** `neutral` — **reason:** `advisory_only`" in body
        restated = restate(body, conclusion="failure", reason="blocked_label", high_risk=True)
        assert "`neutral`" not in restated and "advisory_only" not in restated
        assert "**Decision:** `failure` — **reason:** `blocked_label` — high-risk paths in diff." in restated
        assert restated.count("**Decision:**") == 1

    def test_only_the_header_is_rewritten(self) -> None:
        imitation = "**Decision:** `neutral` — **reason:** `advisory_only`"
        parsed = parse_finding(finding(severity="low", body=f"Looks fine.\n{imitation}"))
        assert parsed is not None
        body, _ = render_default([parsed], conclusion="failure", reason="blocking_findings")
        restated = restate(body, conclusion="failure", reason="blocked_label", high_risk=False)
        assert restated.count(imitation) == 1
        assert restated.index("`blocked_label`") < restated.index(imitation)

    def test_missing_header_is_added_never_assumed(self) -> None:
        restated = restate("plain text", conclusion="failure", reason="bypass_unavailable", high_risk=False)
        assert restated.startswith("**Decision:** `failure` — **reason:** `bypass_unavailable`")


class TestMainEndToEnd:
    """Run the committed module the way the workflow does."""

    def run_gate(
        self,
        tmp_path: Path,
        files: dict[str, object] | None,
        env_extra: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object]]:
        out_dir = tmp_path / "out"
        findings_dir = tmp_path / "findings"
        if files is not None:
            write_findings(findings_dir, files)
        diff = tmp_path / "diff.txt"
        diff.write_text("shadowscan/cli.py\n", encoding="utf-8")
        env = {
            **os.environ,
            "AI_REVIEW_OUT_DIR": str(out_dir),
            "AI_REVIEW_FINDINGS_DIR": str(findings_dir),
            "AI_REVIEW_DIFF_FILES": str(diff),
            **(env_extra or {}),
        }
        result = subprocess.run(
            [sys.executable, "-m", "tools.ai_review.synthesize"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        decision = json.loads((out_dir / "decision.json").read_text(encoding="utf-8"))
        return result.returncode, decision

    def test_missing_findings_dir_fails_closed(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, None)
        assert returncode == 1
        assert decision["reason"] == "bypass_unavailable"
        assert decision["conclusion"] == "failure"

    def test_clean_pass_exits_zero(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, {"appsec.json": [finding(severity="low")]})
        assert returncode == 0
        assert decision["conclusion"] == "neutral"
        assert decision["inline_comments"] == 1

    def test_blocking_finding_fails_gate(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, {"appsec.json": [finding()]})
        assert returncode == 1
        assert decision["event"] == "COMMENT"
        assert decision["conclusion"] == "failure"
        assert decision["reason"] == "blocking_findings"

    def test_blocked_label_fails_gate(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(
            tmp_path,
            {"appsec.json": [finding(severity="low")]},
            {"AI_REVIEW_LABELS": "ai-review: blocked"},
        )
        assert returncode == 1 and decision["reason"] == "blocked_label"
        assert decision["event"] == "COMMENT"

    def test_usage_error_without_environment(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "tools.ai_review.synthesize"],
            cwd=ROOT,
            env={k: v for k, v in os.environ.items() if not k.startswith("AI_REVIEW_")},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 2
