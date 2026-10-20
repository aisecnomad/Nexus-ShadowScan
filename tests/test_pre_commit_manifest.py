"""The consumer hook is loadable and invokes the staged CLI without filename arguments."""

import shlex
from pathlib import Path

from pre_commit.clientlib import load_manifest

from shadowscan.cli import code


def test_consumer_hook_selects_the_index_and_preserves_failure_policy():
    manifest = Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml"
    hooks = load_manifest(str(manifest))
    hook = next(item for item in hooks if item["id"] == "shadowscan-staged")
    assert hook["language"] == "python"
    assert hook["pass_filenames"] is False
    assert hook["always_run"] is True
    assert hook["require_serial"] is True
    assert hook["stages"] == ["pre-commit"]
    argv = shlex.split(hook["entry"])
    assert argv[:2] == ["shadowscan", "code"]
    with code.make_context("code", [*argv[2:], *hook["args"]]) as context:
        assert context.params["quick"] is True
        assert context.params["paths"] == ()
        assert context.params["fail_on"] == "high"
        assert context.params["max_coverage_gap"] == 0
