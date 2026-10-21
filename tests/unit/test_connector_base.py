"""BaseConnector and ConnectorContext: sanitizer limits and diagnostic caps."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.base import (
    INCOMPLETE_REASONS,
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    incomplete_reason,
)
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
        ("code.filesystem: tool.py: import-bound analysis skipped (source did not parse)", "unparsed-input"),
        ("code.filesystem: t.py: model identifiers read from the first 400 literals only", "analysis-limit"),
        ("code.filesystem: repo: triage scan: findings are a subset of a full scan", "subset-scan"),
        ("code.filesystem: data.bin: skipped, never read", "unscanned-input"),
        ("code.filesystem: src/a.py: binary or undecodable content in analyzable file", "unparsed-input"),
        ("something else entirely", "other"),
    ],
)
def test_incomplete_reasons_are_classified_from_the_message_vocabulary(message, reason):
    assert incomplete_reason(message) == reason
    assert reason in INCOMPLETE_REASONS


@pytest.mark.parametrize(
    ("path", "detail", "reason"),
    [
        ("src/http_client.py", "binary or undecodable content in analyzable file", "unparsed-input"),
        ("src/app/permissions.py", "binary or undecodable content in analyzable file", "unparsed-input"),
        ("src/deadline/worker.py", "file analysis incomplete (RecursionError)", "other"),
        (
            "services/403/app.py",
            "structured parse incomplete (ValueError); excerpts withheld",
            "unscanned-input",
        ),
        ("http", "skipped, file exceeds max_file_size", "oversize-file"),
        ("a", "skipped, file exceeds max_file_size", "oversize-file"),
    ],
)
def test_incomplete_reason_leaves_the_named_path_out(path, detail, reason):
    # The scanned tree names its files: the path must not pick the category.
    message = f"code.filesystem: {path}: {detail}"
    assert incomplete_reason(message, path=path) == reason


def test_coverage_gap_keeps_its_reason_for_the_budget_verdict(index):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    ctx.add_coverage_examined(2)
    ctx.coverage_gap(
        "code.filesystem: http/deadline/403.json: skipped; coverage gap", path="http/deadline/403.json"
    )
    ctx.coverage_gap(
        "code.filesystem: src/http.py: unusual entry", path="src/http.py", reason="unresolved-link"
    )
    ctx.coverage_gap("code.filesystem: src/x.py: odd", path="src/x.py", reason="not-a-category")
    ctx.finalize_coverage()
    assert ctx.stats.incomplete and ctx.stats.coverage is not None
    assert [gap["reason"] for gap in ctx.stats.coverage["details"]] == [
        "unscanned-input",
        "unresolved-link",
        "other",
    ]
    assert ctx.stats.incomplete_reasons == {"unscanned-input": 1, "unresolved-link": 1, "other": 1}
    blinding = ConnectorContext(index=index)
    blinding.stats = ScanStats(connector=_Probe.name, started_at="now")
    blinding.coverage_gap(
        "code.filesystem: src/http_403.py: walk stopped", path="src/http_403.py", blinding=True
    )
    assert blinding.stats.incomplete_reasons == {"other": 1}


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


def test_omitted_findings_count_under_the_sanitization_limit_reason(index):
    # Issue #264: infrastructure diagnostics carry explicit reasons instead of
    # being classified from their text.
    ctx = ConnectorContext(config={}, index=index)
    _Oversized(ctx).run()
    assert ctx.stats is not None
    assert ctx.stats.incomplete_reasons == {"sanitization-limit": 1}


def test_a_connector_error_reason_counts_the_skip(index):
    class _Denied(_Oversized):
        name = "test.denied"

        def collect(self):
            raise ConnectorError("test.denied: token lacks the read scope", reason="access-denied")
            yield  # pragma: no cover

        def analyze(self, records):
            list(records)
            return []

    ctx = ConnectorContext(config={}, index=index)
    stats_findings = _Denied(ctx).run()
    assert stats_findings == []
    assert ctx.stats is not None and ctx.stats.skipped
    assert ctx.stats.incomplete_reasons == {"access-denied": 1}

    # A raise site that names no reason keeps the diagnostic-text classification.
    class _Odd(_Oversized):
        name = "test.odd"

        def collect(self):
            raise ConnectorError("test.odd: deadline exceeded while listing")
            yield  # pragma: no cover

        def analyze(self, records):
            list(records)
            return []

    other = ConnectorContext(config={}, index=index)
    _Odd(other).run()
    assert other.stats is not None and other.stats.incomplete_reasons == {"timeout": 1}
