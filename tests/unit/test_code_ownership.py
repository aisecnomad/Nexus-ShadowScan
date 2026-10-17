"""CODEOWNERS matching, evidence ownership and the ownership step budget."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code import ownership
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.ownership import (
    MAX_OWNERSHIP_STEPS,
    CodeOwnership,
    OwnershipBudget,
    codeowners_match,
)
from shadowscan.connectors.code.project_findings import ProjectFindings
from shadowscan.engine import Engine
from shadowscan.models import ScanStats, now_iso


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_codeowners_globs_apply_to_evidence_files_in_last_match_order(tmp_path: Path, run_connector):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        "* @default\n*.py @python\n/src/** @src\n/src/special.py @special\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "special.py").write_text("from langchain import agents\n")
    (tmp_path / "src" / "other.py").write_text("from langchain import agents\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None  # two evidence files have different owners
    assert project.metadata["codeowners_by_file"] == {
        "src/other.py": "@src",
        "src/special.py": "@special",
    }


def test_codeowners_basename_glob_owns_nested_source(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("*.py @python\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@python"


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_codeowners_root_replaced_before_emission_is_incomplete(
    tmp_path: Path, index, monkeypatch: pytest.MonkeyPatch, replacement: str
):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "agent.py").write_text("from crewai import Agent\n")
    (root / "CODEOWNERS").write_text("* @original\n")
    (outside / "CODEOWNERS").write_text("* @outside\n")
    original_emit = ProjectFindings.emit_findings

    def replace_root(self, scan):
        root.rename(tmp_path / "original")
        if replacement == "symlink":
            root.symlink_to(outside, target_is_directory=True)
        else:
            outside.rename(root)
        yield from original_emit(self, scan)

    monkeypatch.setattr(ProjectFindings, "emit_findings", replace_root)
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(root), "use_git": False})]),
        index,
    ).run()

    assert result.findings
    assert not result.complete
    assert all(finding.owner is None for finding in result.findings)
    assert all("@outside" not in str(finding.metadata) for finding in result.findings)
    assert any(
        "CODEOWNERS; ownership incomplete" in error for stats in result.stats for error in stats.errors
    )


def test_codeowners_root_replaced_after_verification_stays_on_source_descriptor(
    tmp_path: Path, index, monkeypatch: pytest.MonkeyPatch
):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "agent.py").write_text("from crewai import Agent\n")
    (root / "CODEOWNERS").write_text("* @original\n")
    (outside / "CODEOWNERS").write_text("* @outside\n")
    original_read = CodeOwnership._read_codeowners
    changed = False

    def replace_before_read(self, path, directory):
        nonlocal changed
        changed = True
        root.rename(tmp_path / "original")
        root.symlink_to(outside, target_is_directory=True)
        return original_read(self, path, directory)

    monkeypatch.setattr(CodeOwnership, "_read_codeowners", replace_before_read)
    findings, ctx = _run(index, root)

    assert changed
    assert not ctx.stats.errors
    assert findings and all(finding.owner == "@original" for finding in findings)


def test_codeowners_cache_is_refreshed_when_connector_scans_again(tmp_path: Path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    owners = tmp_path / "CODEOWNERS"
    owners.write_text("* @first\n")
    connector = FilesystemConnector(
        ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    )
    assert all(finding.owner == "@first" for finding in connector.run())
    owners.write_text("* @second\n")
    findings = connector.run()
    assert findings and all(finding.owner == "@second" for finding in findings)
    assert connector.ownership._ownership_scan is None


def test_single_file_scan_keeps_ownership_scope(tmp_path: Path, index):
    source = tmp_path / "agent.py"
    source.write_text("from crewai import Agent\n")
    (tmp_path / "CODEOWNERS").write_text("* @parent\n")
    findings, ctx = _run(index, source)
    assert not ctx.stats.errors
    assert findings and all(finding.owner is None for finding in findings)


@pytest.mark.parametrize(
    "parent,next_candidate",
    [(".github", "CODEOWNERS"), ("docs", ".gitlab/CODEOWNERS"), (".gitlab", None)],
)
def test_codeowners_candidate_below_a_file_is_absent(
    tmp_path: Path, index, parent: str, next_candidate: str | None
):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    # A file where a candidate's directory would be: that candidate cannot exist.
    (tmp_path / parent).write_text("not a directory\n")
    if next_candidate:
        (tmp_path / next_candidate).parent.mkdir(exist_ok=True)
        (tmp_path / next_candidate).write_text("* @next\n")

    findings, ctx = _run(index, tmp_path)

    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert findings and all(finding.owner == ("@next" if next_candidate else None) for finding in findings)


def test_codeowners_parent_link_inside_the_tree_stays_unread(tmp_path: Path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "handbook").mkdir()
    (tmp_path / "handbook" / "CODEOWNERS").write_text("* @through-link\n")
    (tmp_path / "docs").symlink_to("handbook", target_is_directory=True)
    (tmp_path / ".gitlab").mkdir()
    (tmp_path / ".gitlab" / "CODEOWNERS").write_text("* @next\n")

    findings, ctx = _run(index, tmp_path)

    # The link fails the walk as a file in the way does (ENOTDIR), but what it
    # names is unknown: neither it nor a later candidate supplies owners.
    assert "code.filesystem: could not read docs/CODEOWNERS" in ctx.stats.errors
    assert findings and all(finding.owner is None for finding in findings)


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("/docs/", "docs/guides/start.md", True),
        ("/docs/", "nested/docs/start.md", False),
        ("apps/", "nested/apps/start.md", True),
        ("/apps/", "nested/apps/start.md", False),
        ("docs/*", "docs/start.md", True),
        ("docs/*", "docs/guides/start.md", False),
        ("**/logs", "deeply/nested/logs/agent.py", True),
    ],
)
def test_codeowners_directory_and_root_patterns(pattern, path, expected):
    assert codeowners_match(pattern, path) is expected


def test_codeowners_later_ownerless_rule_clears_owner(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("/apps/ @team\n/apps/github\n")
    (tmp_path / "apps" / "github").mkdir(parents=True)
    (tmp_path / "apps" / "github" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None


def test_codeowners_large_monorepo_resolves_owners_without_exhausting_the_budget(tmp_path, index):
    rules = ["* @org/everyone"] + [f"/services/service-{i}/ @org/team-{i}" for i in range(2000)]
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("\n".join(rules) + "\n")
    for j in range(120):
        package = tmp_path / "packages" / f"pkg-{j}" / "src" / "agents"
        package.mkdir(parents=True)
        (package / "orchestrator.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _run(index, tmp_path)
    assert time.monotonic() - started < 20
    assert not any("budget exceeded" in error for error in ctx.stats.errors)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@org/everyone"


def test_codeowners_aggregate_budget_marks_later_ownership_incomplete(tmp_path, index, monkeypatch):
    (tmp_path / "CODEOWNERS").write_text("* @org/everyone\n")
    monkeypatch.setattr(ownership, "MAX_ROOT_OWNERSHIP_STEPS", 24)
    ctx = ConnectorContext(config={"path": str(tmp_path)}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso())
    connector = FilesystemConnector(ctx)

    owners = [connector.ownership.owner_for(tmp_path, f"file-{i}.py") for i in range(20)]
    assert owners[0] == "@org/everyone"
    assert owners[-1] is None
    assert connector.ownership._ownership_steps_remaining[tmp_path] == 0
    assert any("CODEOWNERS" in error and "ownership incomplete" in error for error in ctx.stats.errors)
    errors_before = len(ctx.stats.errors)
    assert connector.ownership.owner_for(tmp_path, "still-unknown.py") is None
    assert len(ctx.stats.errors) == errors_before


@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("/services/api/", "services/api/main.py", True),
        ("/services/api/", "packages/api/main.py", False),
        ("/**/api/", "packages/api/x.py", True),
        ("*.py", "a/b/c.py", True),
        ("/docs/*.md", "docs/readme.md", True),
        ("/docs/*.md", "src/docs/readme.md", False),
        ("services/*/agents/", "services/x/agents/run.py", True),
    ],
)
def test_codeowners_first_selector_short_circuit_preserves_semantics(pattern, path, expected):
    assert codeowners_match(pattern, path) is expected


def test_codeowners_non_matching_anchored_rule_is_nearly_free():
    budget = OwnershipBudget()
    assert not codeowners_match("/services/api/", "packages/api/main.py", budget)
    assert budget.remaining >= MAX_OWNERSHIP_STEPS - 5
