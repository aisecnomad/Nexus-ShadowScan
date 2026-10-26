"""The pre-commit scope reads index objects, never the possibly different worktree."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext
from shadowscan.engine import Engine
from shadowscan.incremental import _eligible
from shadowscan.utils import staged
from shadowscan.utils.git import safe_git_env


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], env=safe_git_env(), stderr=subprocess.PIPE, text=True
    ).strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.name", "Synthetic Test")
    _git(tmp_path, "config", "user.email", "synthetic@example.test")
    _git(tmp_path, "config", "gc.auto", "0")
    _git(tmp_path, "config", "maintenance.auto", "false")
    return tmp_path


def _scan(root: Path, index):
    return Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(root), "staged": True})]),
        index=index,
    ).run()


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("staged_ai", [True, False])
def test_quick_scans_index_content_not_unstaged_edits(repository, index, staged_ai):
    ai = (Path(__file__).parents[1] / "fixtures" / "code" / "staged_source" / "app.py").read_text()
    ordinary = "print('ordinary application')\n"
    path = repository / "app.py"
    path.write_text(ai if staged_ai else ordinary)
    _git(repository, "add", "app.py")
    path.write_text(ordinary if staged_ai else ai)
    result = _scan(repository, index)
    assert result.complete, result.stats
    assert bool(result.findings) is staged_ai
    assert result.collection_scope["comparable"] is False
    assert "not a repository inventory" in result.collection_scope["reason"]
    assert any("exact index blobs only" in w for s in result.stats for w in s.warnings)
    for finding in result.findings:
        assert "staged-scan" in finding.tags
        assert finding.metadata["staged_scan"]["files"] == 1
        assert "shadowscan-staged-" not in finding.resource
        assert finding.metadata["scan_root"] == str(repository)
    assert [finding.id for finding in result.findings] == [
        finding.id for finding in _scan(repository, index).findings
    ]


@pytest.mark.requires_git_2_45
def test_empty_and_deleted_only_scopes_are_explicit(repository, index):
    (repository / "old.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    _git(repository, "-c", "commit.gpgSign=false", "commit", "-qm", "synthetic baseline")
    empty = _scan(repository, index)
    assert empty.complete and not empty.findings
    assert any("0 changed file(s), 0 deletion(s)" in w for s in empty.stats for w in s.warnings)
    _git(repository, "rm", "old.py")
    deleted = _scan(repository, index)
    assert deleted.complete and not deleted.findings
    assert deleted.collection_scope["comparable"] is False
    assert any("0 changed file(s), 1 deletion(s)" in w for s in deleted.stats for w in s.warnings)


@pytest.mark.requires_git_2_45
def test_snapshot_preserves_binary_bytes_and_never_executes_source(repository, index):
    content = b"\0\xff\xfe\r\nraw bytes\0"
    (repository / "data.bin").write_bytes(content)
    (repository / "app.py").write_text("raise RuntimeError('scanned code must never run')\n")
    _git(repository, "add", ".")
    ctx = ConnectorContext(config={}, index=index)
    with staged.staged_snapshot(repository, ctx) as snapshot:
        assert (snapshot.root / "data.bin").read_bytes() == content
        assert snapshot.files == 2
    assert not snapshot.root.exists()
    assert _scan(repository, index).complete


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("kind", ["symlink", "submodule", "oversize", "too-many", "total-bytes"])
def test_unsupported_or_over_budget_index_content_is_incomplete(repository, index, monkeypatch, kind):
    (repository / "app.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    if kind == "symlink":
        (repository / "link.py").symlink_to("app.py")
        _git(repository, "add", "link.py")
    elif kind == "submodule":
        oid = _git(repository, "rev-parse", ":app.py")
        _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{oid},module")
    elif kind == "oversize":
        monkeypatch.setattr(staged, "MAX_STAGED_FILE_BYTES", 8)
    elif kind == "total-bytes":
        monkeypatch.setattr(staged, "MAX_STAGED_BYTES", 8)
    else:
        monkeypatch.setattr(staged, "MAX_STAGED_FILES", 1)
        (repository / "second.py").write_text("pass\n")
        _git(repository, "add", ".")
    result = _scan(repository, index)
    assert not result.complete
    assert not result.findings
    assert result.summary()["incomplete_reasons"] == {"unscanned-input": 1}


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("ignored_by", ["tracked", "worktree-only", "config", "new-submodule"])
def test_submodule_ignore_settings_cannot_hide_a_staged_gitlink(repository, index, ignored_by):
    declaration = '[submodule "module"]\n\tpath = module\n\turl = https://example.test/module.git\n'
    ignore_all = declaration + "\tignore = all\n"
    (repository / "app.py").write_text("print('ordinary application')\n")
    (repository / ".gitmodules").write_text(ignore_all if ignored_by == "tracked" else declaration)
    _git(repository, "add", "app.py", *([] if ignored_by == "new-submodule" else [".gitmodules"]))
    if ignored_by != "new-submodule":
        oid = _git(repository, "rev-parse", ":app.py")
        _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{oid},module")
    _git(repository, "-c", "commit.gpgSign=false", "commit", "-qm", "synthetic baseline")
    if ignored_by in {"worktree-only", "new-submodule"}:
        # Git reads the worktree copy even when it is unstaged or untracked.
        (repository / ".gitmodules").write_text(ignore_all)
    elif ignored_by == "config":
        _git(repository, "config", "diff.ignoreSubmodules", "all")
    head = _git(repository, "rev-parse", "HEAD")
    _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{head},module")
    assert _git(repository, "diff", "--cached", "--name-only", "--ignore-submodules=none") == "module"
    result = _scan(repository, index)
    assert not result.complete
    assert not result.findings
    assert result.summary()["incomplete_reasons"] == {"unscanned-input": 1}
    assert any("submodules" in error for stat in result.stats for error in stat.errors)


@pytest.mark.requires_git_2_45
def test_git_filters_hooks_external_diff_and_fsmonitor_do_not_execute(repository, index):
    (repository / "app.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    marker = repository / "MUST_NOT_EXIST"
    command = f"touch {marker}"
    for key in ("core.fsmonitor", "diff.external", "filter.hostile.smudge", "filter.hostile.clean"):
        _git(repository, "config", key, command)
    (repository / ".gitattributes").write_text("* filter=hostile diff=hostile\n")
    hooks = repository / ".git" / "hooks"
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\n{command}\n")
    hook.chmod(0o755)
    result = _scan(repository, index)
    assert result.complete and result.findings
    assert not marker.exists()


@pytest.mark.requires_git_2_45
def test_missing_objects_and_metadata_indirections_fail_closed(repository, index):
    (repository / "app.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    oid = _git(repository, "rev-parse", ":app.py")
    (repository / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
    result = _scan(repository, index)
    assert not result.complete and not result.findings
    _git(repository, "config", "include.path", "/not/read/by/scanner")
    result = _scan(repository, index)
    assert not result.complete


@pytest.mark.parametrize(
    "path", [b"../escape", b"/absolute", b".git/config", b"a/.GIT/config", b"a//b", b"a\\b", b"\xff.py"]
)
def test_staged_paths_cannot_escape_or_change_identity(path):
    with pytest.raises((staged.StagedScanError, UnicodeDecodeError)):
        staged._safe_path(path)


def test_staged_results_are_never_reused_from_worktree_cache(tmp_path):
    assert not _eligible(ConnectorSpec("code.filesystem", {"path": str(tmp_path), "staged": True}))


@pytest.mark.parametrize(
    "content", [b"bad response", b"0" * 40 + b" missing\n", b"0" * 40 + b" blob 5\nab\n"]
)
def test_missing_or_truncated_batch_blobs_never_materialize_as_clean_source(tmp_path, content):
    with pytest.raises(staged.StagedScanError):
        staged._materialize(tmp_path, [("app.py", b"0" * 40)], content)
    assert not (tmp_path / "app.py").exists()


@pytest.mark.parametrize("extra", [["--github-repo", "a/b"], ["--diff-base", "main"], ["--triage"]])
def test_quick_rejects_incompatible_scope_options(extra):
    result = CliRunner().invoke(main, ["code", "--quick", *extra])
    assert result.exit_code == 1
    assert "--quick requires local Git roots" in result.output


@pytest.mark.requires_git_2_45
def test_quick_cli_defaults_to_current_root_and_keeps_policy_exit(repository, monkeypatch):
    (repository / "app.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    monkeypatch.chdir(repository)
    result = CliRunner().invoke(main, ["code", "--quick", "--format", "json", "--fail-on", "info"])
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["status"] == "complete"
    assert report["collection_scope"]["comparable"] is False
    assert report["findings"]


@pytest.mark.requires_git_2_45
def test_quick_cli_missing_git_root_is_exit_three(tmp_path):
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--quick", "--format", "json"])
    assert result.exit_code == 3
    report = json.loads(result.stdout)
    assert report["summary"]["status"] == "incomplete"
    assert "use a full scan" in report["stats"][0]["errors"][0]


def test_git_metadata_environment_never_forwards_an_inherited_index(monkeypatch):
    monkeypatch.setenv("GIT_INDEX_FILE", "/should/not/read")
    env = staged.metadata_git_env()
    assert "GIT_INDEX_FILE" not in env


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("inherited", [None, "absolute", "relative"])
def test_quick_accepts_only_the_ordinary_commit_index(repository, monkeypatch, index, inherited):
    (repository / "app.py").write_text("from openai import OpenAI\n")
    _git(repository, "add", ".")
    monkeypatch.chdir(repository)
    if inherited is None:
        monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    else:
        value = str(repository / ".git" / "index") if inherited == "absolute" else ".git/index"
        monkeypatch.setenv("GIT_INDEX_FILE", value)
    result = _scan(repository, index)
    assert result.complete and result.findings
    preflight = CliRunner().invoke(main, ["code", "--quick", "--preflight", "--format", "json"])
    assert preflight.exit_code == 0
    assert json.loads(preflight.stdout)["roots"][0]["staged_files"] == 1


@pytest.mark.parametrize("extra", [[], ["--preflight"]], ids=["scan", "preflight"])
@pytest.mark.parametrize("inherited", ["index.lock", "next-index-123.lock", "external", "foreign-relative"])
def test_quick_refuses_alternate_commit_indexes_before_git_reads(repository, monkeypatch, extra, inherited):
    def forbidden(*args, **kwargs):
        raise AssertionError("alternate index must be refused before invoking Git")

    monkeypatch.setattr(staged, "_git", forbidden)
    if inherited == "external":
        value = "/SHOULD_NOT_READ_OR_ECHO/external-index"
    elif inherited == "foreign-relative":
        foreign = repository / "foreign"
        foreign.mkdir()
        monkeypatch.chdir(foreign)
        value = ".git/index"
    else:
        value = str(repository / ".git" / inherited)
    monkeypatch.setenv("GIT_INDEX_FILE", value)
    result = CliRunner().invoke(main, ["code", str(repository), "--quick", *extra, "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert "alternate Git index" in result.stdout
    assert "git add" in result.stdout
    assert value not in result.stdout
    if extra:
        assert report["ready"] is False and report["scan_performed"] is False
    else:
        assert report["summary"]["complete"] is False
        assert report["findings"] == []
        assert report["summary"]["incomplete_reasons"] == {"unscanned-input": 1}


@pytest.mark.requires_git_2_45
def test_preflight_reads_staged_scope_without_running_analysis(repository, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not run an engine")

    monkeypatch.setattr(Engine, "run", forbidden)
    monkeypatch.setattr("shadowscan.connectors.base.get_index", forbidden)
    (repository / "app.py").write_text("raise RuntimeError('inert source')\n")
    _git(repository, "add", ".")
    result = CliRunner().invoke(main, ["code", str(repository), "--quick", "--preflight", "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["scan_performed"] is False and report["ready"] is True
    assert report["roots"][0]["staged_files"] == 1
    assert "summary" not in report and "findings" not in report


def test_preflight_reports_blocked_and_local_ready_separately(tmp_path):
    blocked = CliRunner().invoke(main, ["code", str(tmp_path), "--quick", "--preflight", "--format", "json"])
    assert blocked.exit_code == 3
    assert json.loads(blocked.stdout)["ready"] is False
    ordinary = CliRunner().invoke(main, ["code", str(tmp_path), "--preflight", "--format", "json"])
    assert ordinary.exit_code == 0, ordinary.output
    report = json.loads(ordinary.stdout)
    assert report["scan_performed"] is False
    assert report["roots"][0]["connector_timeout_seconds"] == 120
