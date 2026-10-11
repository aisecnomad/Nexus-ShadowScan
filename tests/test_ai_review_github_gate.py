from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml

from tools.ai_review import synthesize
from tools.ai_review.github_gate import (
    GateError,
    GitHub,
    diff_digest,
    high_risk,
    main,
    prepare,
    publish,
    snapshot,
    validate_evidence,
)
from tools.ai_review.schema import AGENTS

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
FILES = [{"filename": "shadowscan/cli.py", "sha": "b" * 40, "status": "modified"}]


class FakeGitHub(GitHub):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.labels: list[dict[str, str]] = []
        self.head = HEAD
        self.files: list[dict[str, Any]] = FILES
        self.fail_review = False
        self.file_fetches = 0

    def request(self, endpoint: str, payload: dict[str, Any] | None = None) -> Any:
        self.calls.append((endpoint, payload))
        if endpoint == "pulls/1":
            return {"head": {"sha": self.head}, "changed_files": len(self.files)}
        if endpoint == "pulls/1/reviews" and self.fail_review:
            raise GateError("denied")
        return {"id": 42}

    def pages(self, endpoint: str) -> list[Any]:
        if endpoint.endswith("/files"):
            self.file_fetches += 1
            return self.files
        return self.labels


def evidence(root: Path, severity: str = "low", files_per_role: int = 1, padding: int = 0) -> None:
    """Six roles' evidence; ``padding`` lengthens every structured field."""
    root.mkdir()
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "diff_digest": diff_digest(FILES),
                "agents": sorted(set(AGENTS) - {"orchestrator"}),
            }
        )
    )
    (root / "scanner-fingerprints.json").write_text("[]")
    for role in set(AGENTS) - {"orchestrator"}:
        directory = root / "findings" / role
        directory.mkdir(parents=True)
        for index in range(files_per_role):
            (directory / f"findings-{index}.json").write_text(
                json.dumps(
                    [
                        {
                            "schema_version": "1",
                            "agent": role,
                            "severity": severity,
                            "category": "security",
                            "title": f"{role} finding {index}",
                            "body": "details",
                            "path": FILES[0]["filename"],
                            "line": index + 1,
                            "scenario": "A bounded failure scenario" + "s" * padding,
                            "recommendation": "Validate input" + "r" * padding,
                            "assumptions": "No upstream validation" + "a" * padding,
                            "confidence": "high",
                        }
                    ]
                )
            )


def review_body(api: FakeGitHub) -> str:
    review = next(payload for endpoint, payload in api.calls if endpoint.endswith("/reviews"))
    assert review is not None and review["event"] == "COMMENT"
    return str(review["body"])


def decision_header(body: str) -> str:
    return next(line for line in body.splitlines() if line.startswith("**Decision:**"))


def test_missing_evidence_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context():
        out = tmp_path / "out"
        assert prepare(FakeGitHub(), 1, HEAD, tmp_path / "missing", out) == 1
        assert json.loads((out / "decision.json").read_text())["reason"] == "bypass_unavailable"


@pytest.mark.parametrize("severity,expected", [("low", 0), ("high", 1)])
def test_prepare_and_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    severity: str,
    expected: int,
) -> None:
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root, severity)
    with monkeypatch.context():
        api = FakeGitHub()
        assert prepare(api, 1, HEAD, root, out) == expected
        assert api.file_fetches == 1
        assert publish(api, 1, HEAD, out, False) == expected
        assert sum(endpoint == "pulls/1/reviews" for endpoint, _ in api.calls) == 1
        assert sum(endpoint == "check-runs" for endpoint, _ in api.calls) == 1
        assert api.calls[-1][1]["conclusion"] == ("neutral" if expected == 0 else "failure")


def test_blocked_label_overrides_unavailable(tmp_path: Path) -> None:
    api = FakeGitHub()
    api.labels = [{"name": "ai-review: blocked"}]
    assert publish(api, 1, HEAD, tmp_path, True) == 1
    # A bot that never approves never requests changes: the check carries the verdict.
    body = review_body(api)
    assert decision_header(body) == "**Decision:** `failure` — **reason:** `blocked_label`"
    assert api.calls[-1][1] is not None and api.calls[-1][1]["conclusion"] == "failure"


def test_blocking_findings_post_a_comment_and_fail_the_check(tmp_path: Path) -> None:
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root, "high")
    api = FakeGitHub()
    assert prepare(api, 1, HEAD, root, out) == 1
    assert publish(api, 1, HEAD, out, False) == 1
    body = review_body(api)
    assert (
        decision_header(body)
        == "**Decision:** `failure` — **reason:** `blocking_findings` — high-risk paths in diff."
    )
    assert api.calls[-1][1] is not None and api.calls[-1][1]["conclusion"] == "failure"
    assert "REQUEST_CHANGES" not in json.dumps(api.calls)


def test_invalid_evidence_still_publishes_the_failed_review(tmp_path: Path) -> None:
    # The digest derives from the API, not the evidence: a validation failure
    # must still reach the review as malformed_findings instead of an exception.
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root)
    (root / "manifest.json").write_text("{}")
    api = FakeGitHub()
    assert prepare(api, 1, HEAD, root, out) == 1
    assert publish(api, 1, HEAD, out, False) == 1
    body = review_body(api)
    assert (
        decision_header(body)
        == "**Decision:** `failure` — **reason:** `malformed_findings` — high-risk paths in diff."
    )
    assert api.calls[-1][1] is not None and api.calls[-1][1]["conclusion"] == "failure"


@pytest.mark.parametrize("override", ["preflight", "label"])
def test_late_override_restates_the_decision_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: str
) -> None:
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root)
    api = FakeGitHub()
    assert prepare(api, 1, HEAD, root, out) == 0
    if override == "preflight":
        monkeypatch.setenv("AI_REVIEW_PREFLIGHT_RESULT", "failure")
        reason = "bypass_unavailable"
    else:
        api.labels = [{"name": "ai-review: blocked"}]
        reason = "blocked_label"
    assert publish(api, 1, HEAD, out, False) == 1
    body = review_body(api)
    assert (
        decision_header(body)
        == f"**Decision:** `failure` — **reason:** `{reason}` — high-risk paths in diff."
    )
    assert "`neutral`" not in body and "advisory_only" not in body
    assert api.calls[-1][1] is not None and api.calls[-1][1]["conclusion"] == "failure"


def test_validated_multi_file_evidence_synthesizes(tmp_path: Path) -> None:
    # Six roles with several files each stay under one aggregate limit that
    # validation enforces before copying, so what validates also synthesizes.
    root, out = tmp_path / "input", tmp_path / "out"
    roles = len(set(AGENTS) - {"orchestrator"})
    evidence(root, files_per_role=synthesize.MAX_FINDINGS_FILES // roles)
    api = FakeGitHub()
    assert prepare(api, 1, HEAD, root, out) == 0
    assert json.loads((out / "decision.json").read_text())["reason"] == "advisory_only"


def test_aggregate_artifact_limit_is_enforced_before_copying(tmp_path: Path) -> None:
    root, out = tmp_path / "input", tmp_path / "out"
    roles = len(set(AGENTS) - {"orchestrator"})
    evidence(root, files_per_role=synthesize.MAX_FINDINGS_FILES // roles + 1)
    with pytest.raises(GateError, match="artifact limit"):
        validate_evidence(root, diff_digest(FILES))
    assert prepare(FakeGitHub(), 1, HEAD, root, out) == 1
    assert json.loads((out / "decision.json").read_text())["reason"] == "malformed_findings"
    assert not (out / "validated").exists()


def test_symlinked_role_directory_is_malformed_evidence(tmp_path: Path) -> None:
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root)
    outside = tmp_path / "outside"
    (root / "findings" / "appsec").rename(outside)
    (root / "findings" / "appsec").symlink_to(outside, target_is_directory=True)
    with pytest.raises(GateError, match="specialist evidence malformed or unavailable"):
        validate_evidence(root, diff_digest(FILES))
    assert prepare(FakeGitHub(), 1, HEAD, root, out) == 1
    assert json.loads((out / "decision.json").read_text())["reason"] == "malformed_findings"


def test_review_body_stays_within_github_limit(tmp_path: Path) -> None:
    # Nine maximum-size findings would exceed GitHub's 65,536-character body.
    root, out = tmp_path / "input", tmp_path / "out"
    evidence(root, "high", files_per_role=2, padding=2400)
    api = FakeGitHub()
    assert prepare(api, 1, HEAD, root, out) == 1
    assert publish(api, 1, HEAD, out, False) == 1
    body = review_body(api)
    assert len(body) <= 65_536
    assert json.loads((out / "decision.json").read_text())["findings"] == 12
    for role in set(AGENTS) - {"orchestrator"}:
        assert f"{role} finding 1" in body
    assert "`shadowscan/cli.py:2`" in body


def test_snapshot_rejects_line_breaks_in_diff_paths() -> None:
    api = FakeGitHub()
    api.files = [{**FILES[0], "filename": "shadowscan/cli.py\ntools/other.py"}]
    with pytest.raises(GateError, match="diff paths malformed"):
        snapshot(api, 1, HEAD)


def test_review_denied_fails_check(tmp_path: Path) -> None:
    api = FakeGitHub()
    api.fail_review = True
    with pytest.raises(GateError):
        publish(api, 1, HEAD, tmp_path, True)
    assert api.calls[-1][1]["conclusion"] == "failure"


def test_superseded_head_fails() -> None:
    api = FakeGitHub()
    api.head = "c" * 40
    with pytest.raises(GateError):
        snapshot(api, 1, HEAD)


def test_manifest_and_roles_required(tmp_path: Path) -> None:
    root = tmp_path / "input"
    evidence(root)
    validate_evidence(root, diff_digest(FILES))
    with pytest.raises(GateError):
        validate_evidence(root, "stale")
    path = root / "findings" / "appsec" / "findings-0.json"
    data = json.loads(path.read_text())
    del data[0]["assumptions"]
    path.write_text(json.dumps(data))
    with pytest.raises(GateError):
        validate_evidence(root, diff_digest(FILES))


def test_malformed_manifest_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "input"
    evidence(root)
    (root / "manifest.json").write_text("{}")
    with monkeypatch.context():
        out = tmp_path / "out"
        assert prepare(FakeGitHub(), 1, HEAD, root, out) == 1
        assert json.loads((out / "decision.json").read_text())["reason"] == "malformed_findings"


def test_digest_and_high_risk() -> None:
    assert diff_digest(FILES) == diff_digest(FILES + [{"filename": ".github/ai-review/manifest.json"}])
    assert high_risk(["docs/guide.md"]) is False
    assert high_risk(["shadowscan/cli.py"]) is True
    assert high_risk(["unknown.sh"]) is True


def test_digest_binds_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PR_BASE_SHA", "a" * 40)
    first = diff_digest(FILES)
    monkeypatch.setenv("PR_BASE_SHA", "b" * 40)
    assert diff_digest(FILES) != first


def test_digest_binds_rename_source() -> None:
    first = [{**FILES[0], "status": "renamed", "previous_filename": "source-a.py"}]
    second = [{**FILES[0], "status": "renamed", "previous_filename": "source-b.py"}]
    assert diff_digest(first) != diff_digest(second)


def test_pending_check_precedes_failed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = FakeGitHub()
    api.head = "c" * 40
    monkeypatch.setattr("tools.ai_review.github_gate.GitHub", lambda: api)
    monkeypatch.setattr("sys.argv", ["github_gate", "publish"])
    for name, value in {
        "PR_NUMBER": "1",
        "PR_HEAD_SHA": HEAD,
        "AI_REVIEW_INPUT": str(tmp_path / "missing"),
        "AI_REVIEW_OUT_DIR": str(tmp_path / "out"),
    }.items():
        monkeypatch.setenv(name, value)
    assert main() == 1
    assert api.calls[0][0] == "check-runs"
    assert api.calls[-1][1]["conclusion"] == "failure"


def test_workflow_security_boundary() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ai-review-gate.yml").read_text())
    assert set(workflow[True]) == {"pull_request"}
    assert workflow[True]["pull_request"]["types"] == [
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    ]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["preflight"]["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    publisher = workflow["jobs"]["orchestrator"]
    assert publisher["if"] == "always()"
    assert publisher["needs"] == "preflight"
    publish_step = next(step for step in publisher["steps"] if "run" in step)
    assert publish_step["env"]["AI_REVIEW_PREFLIGHT_RESULT"] == "${{ needs.preflight.result }}"
    assert publisher["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
        "checks": "write",
    }
    for job in workflow["jobs"].values():
        run = next(step for step in job["steps"] if "run" in step)
        assert run["working-directory"] == "trusted"
        checkout = job["steps"][0]["with"]
        assert checkout["ref"] == "${{ github.event.pull_request.base.sha }}"
        assert checkout["persist-credentials"] is False


def test_transport_patch_and_fixed_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "aisecnomad/Project-Nexus")
    monkeypatch.setenv("GH_TOKEN", "test-only-placeholder")
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = io.BytesIO(b'{"id":42}')
    builder = Mock(return_value=opener)
    monkeypatch.setattr("urllib.request.build_opener", builder)
    api = GitHub()
    assert api.request("check-runs/42", {"status": "completed"}) == {"id": 42}
    request = opener.open.call_args.args[0]
    assert request.get_method() == "PATCH"
    assert request.full_url.startswith("https://api.github.com/repos/")
    handler = builder.call_args.args[0]()
    assert handler.redirect_request(None, None, 302, "", {}, "http://untrusted.invalid") is None
    opener.open.side_effect = OSError("unsanitized response")
    with pytest.raises(GateError, match="GitHub API unavailable or malformed") as error:
        api.request("pulls/1")
    assert "unsanitized" not in str(error.value)


def test_pagination_malformed_and_limit() -> None:
    api = FakeGitHub()
    api.request = Mock(return_value={})  # type: ignore[method-assign]
    with pytest.raises(GateError, match="list malformed"):
        GitHub.pages(api, "pulls/1/files")
    api.request = Mock(return_value=[{}] * 100)  # type: ignore[method-assign]
    with pytest.raises(GateError, match="pagination limit"):
        GitHub.pages(api, "pulls/1/files")
