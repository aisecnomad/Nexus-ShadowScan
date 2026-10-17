"""BaseConnector and ConnectorContext: sanitizer limits and diagnostic caps."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.base import INCOMPLETE_REASONS, BaseConnector, ConnectorContext, incomplete_reason
from shadowscan.models import Finding, Kind, ScanStats, Surface

KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def _finding(title: str, **kwargs) -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="test.records",
        kind=Kind.AGENT,
        title=title,
        resource=f"repo:{title}",
        resource_type="repository",
        **kwargs,
    )


class _Oversized(BaseConnector):
    """Yields an ordinary finding, one whose aggregate exceeds the sanitizer budget, then a credential finding."""

    name = "test.records"

    def collect(self):
        yield {"id": 1}

    def analyze(self, records):
        yield _finding("first")
        huge = _finding("aggregate")
        # Individually bounded pieces whose expanded serialization exceeds the budget.
        huge.metadata["agent_definitions"] = [{"tools": ["tool"] * 1000}] * 200
        yield huge
        secret = _finding("credential")
        secret.metadata["excerpt"] = f"OPENAI_API_KEY={KEY}"
        yield secret


class _Probe(BaseConnector):
    name = "test.offline"

    def collect(self):
        return []

    def analyze(self, records):
        return []


def test_one_oversized_finding_is_omitted_without_discarding_the_others(index):
    ctx = ConnectorContext(config={}, index=index)
    findings = _Oversized(ctx).run()
    assert [f.title for f in findings] == ["first", "credential"]
    assert ctx.stats is not None and ctx.stats.incomplete
    assert any("finding omitted: sanitization safety limit exceeded" in e for e in ctx.stats.errors)
    assert KEY not in json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (
            "code.filesystem: data.json: skipped, file exceeds max_file_size; coverage incomplete",
            "oversize-file",
        ),
        (
            "code.filesystem: skipped symbolic link tests/ca whose target is unavailable or unscanned",
            "unresolved-link",
        ),
        (
            "code.filesystem: a.json: structured sanitization incomplete (SanitizationLimitError)",
            "sanitization-limit",
        ),
        ("code.filesystem: big.yaml: credential detection incomplete (MatchTimeoutError)", "timeout"),
        ("cloud.aws: connector deadline reached after 10 of 20 files; results incomplete", "timeout"),
        ("saas.slack: HTTP 403 Forbidden from the users list", "access-denied"),
        ("identity.okta: rate limit reached; collection incomplete", "upstream-error"),
        ("gateway.logs: connection reset by the upstream", "upstream-error"),
        (
            "code.filesystem: mkdocs.yml: invalid structured configuration syntax; checks skipped",
            "unparsed-input",
        ),
        ("code.filesystem: t.py: model identifiers read from the first 400 literals only", "analysis-limit"),
        ("code.filesystem: repo: triage scan: findings are a subset of a full scan", "subset-scan"),
        ("code.filesystem: data.bin: skipped, never read", "unscanned-input"),
        ("something else entirely", "other"),
    ],
)
def test_incomplete_reasons_are_classified_from_the_message_vocabulary(message, reason):
    assert incomplete_reason(message) == reason
    assert reason in INCOMPLETE_REASONS


def test_context_counts_incomplete_reasons_and_declared_omissions(index):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    ctx.warn("code.filesystem: notes.md: skipped, never read", incomplete=False)
    ctx.warn(
        "code.filesystem: data.json: skipped, file exceeds max_file_size; declared",
        incomplete=False,
        declared=True,
    )
    assert not ctx.stats.incomplete and ctx.stats.incomplete_reasons == {}
    assert ctx.stats.declared_omissions == 1
    ctx.warn("code.filesystem: data.json: skipped, file exceeds max_file_size; coverage incomplete")
    ctx.error("saas.slack: HTTP 403 Forbidden", reason="access-denied")
    ctx.error("saas.slack: something odd", reason="not-a-category")
    assert ctx.stats.incomplete
    assert ctx.stats.incomplete_reasons == {"oversize-file": 1, "access-denied": 1, "other": 1}


def test_context_diagnostic_limits_preserve_failure_status(monkeypatch, index, caplog):
    monkeypatch.setattr(ConnectorContext, "_MAX_DIAGNOSTICS", 2)
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    for _ in range(10):
        ctx.warn("optional", incomplete=False)
    assert not ctx.stats.incomplete
    # A suppressed diagnostic must still mark missing required coverage.
    ctx.warn("required", incomplete=True)
    for _ in range(10):
        ctx.error("invalid record")
    assert ctx.stats.incomplete
    assert len(ctx.stats.errors) == len(ctx.stats.warnings) == 3
    assert len(caplog.records) == 6
    assert "diagnostic limit" in ctx.stats.errors[-1]
    # The reasons count every incomplete diagnostic, past the message limit too.
    assert ctx.stats.incomplete_reasons == {"other": 1, "unparsed-input": 10}
