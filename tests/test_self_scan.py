"""The self-scan stays an explained, narrow list of exclusions that make and CI run alike.

`examples/shadowscan.self-scan.yaml` lets `make self-scan` and CI scan this repository with its
own scanner and require a complete report (exit 0), although a few files deliberately trip
scanner limits. The scanner fails closed on such a file, so each exclusion is a reviewed decision
to stop reading a path. These tests keep every exclusion explained, real and no broader than it
says (output that git ignores, such as the built docs, may be missing from a clean checkout), keep
the first-party code, tests and workflows out of the list unless a test below names the
exception, and keep `make self-scan`, CI and the documents describing both in step.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from shadowscan.connectors.code.filesystem import DEFAULT_EXCLUDES

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "examples" / "shadowscan.self-scan.yaml"
COMMAND = "shadowscan scan -c examples/shadowscan.self-scan.yaml --format json -o "

# Trees that hold what ships, builds, releases, documents or tests the project. Excluding one
# whole, or any part of it that is not listed in ALLOWED_INSIDE_PROTECTED_TREES, needs a change
# to this test next to the change to the configuration, so a reviewer sees both together.
PROTECTED_TREES = frozenset({".github", "docs", "examples", "shadowscan", "tests", "tools"})
ALLOWED_INSIDE_PROTECTED_TREES = frozenset(
    {
        # Sample repositories built to look like shadow AI agents: the scanner's own inputs.
        "tests/fixtures",
        # The engineering log quotes the credential-shaped inputs of every review, past the
        # five-per-format quota the scanner discloses as incomplete.
        "docs/engineering-log.md",
        # Hundreds of synthetic credentials with their expected outcomes: past the quota by design.
        "tests/unit/test_credential_oracle.py",
        "tests/unit/test_generic_credential_references.py",
    }
)

# Output a repository command writes into the checkout, which git ignores: a clean checkout has none,
# so an exclusion named here may match nothing. Each maps to the .gitignore line that keeps it from
# being tracked; an exclusion that is not tracked cannot hide a file anyone reviews.
GENERATED = {
    # `make docs` (mkdocs build) writes the documentation site here.
    "site": "/site/",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@functools.cache
def _config() -> dict[str, Any]:
    loaded = yaml.safe_load(_text(CONFIG))
    assert isinstance(loaded, dict)
    return loaded


def _exclusions() -> list[str]:
    (connector,) = _config()["connectors"]
    exclusions = connector["exclude"]
    assert isinstance(exclusions, list) and exclusions, "the configuration lists no exclusions"
    assert all(isinstance(entry, str) for entry in exclusions)
    return exclusions


def test_the_configuration_scans_the_checkout_and_only_adds_exclusions() -> None:
    config = _config()
    assert set(config) == {"connectors"}
    (connector,) = config["connectors"]
    # Any other option (a larger file limit, skipped-file globs, switched-off default exclusions,
    # an inventory inside the scanned tree) would change what a complete scan means.
    assert set(connector) == {"name", "paths", "exclude"}
    assert connector["name"] == "code.filesystem"
    # Relative paths resolve beside the configuration file, so ".." is the repository root.
    assert connector["paths"] == [".."]
    assert (CONFIG.parent / connector["paths"][0]).resolve() == ROOT


def test_optional_companion_is_out_of_scope_but_the_local_benchmark_guide_is_scanned() -> None:
    assert "benchmark-suite" in _exclusions()
    assert "benchmarks" not in _exclusions()
    assert (ROOT / "benchmarks" / "README.md").is_file()
    workflow = yaml.safe_load(_text(ROOT / ".github" / "workflows" / "ci.yml"))
    assert "benchmark-tests" in workflow["jobs"]["gate"]["needs"]
    steps = workflow["jobs"]["benchmark-tests"]["steps"]
    assert any("python -m tools.benchmark_suite" in step.get("run", "") for step in steps)
    assert any("python -m tools.benchmark_complexity" in step.get("run", "") for step in steps)


def test_each_exclusion_is_a_plain_unique_path_with_a_reason_above_it() -> None:
    lines = _text(CONFIG).splitlines()
    exclusions = _exclusions()
    assert len(set(exclusions)) == len(exclusions), "an exclusion is listed twice"
    for entry in exclusions:
        path = PurePosixPath(entry)
        assert str(path) == entry and not path.is_absolute(), f"{entry}: write a normalized relative path"
        assert ".." not in path.parts and "." not in path.parts, entry
        # A pattern can grow to cover files nobody looked at; a path names exactly what is skipped.
        assert not re.search(r"[*?\[\]{}]", entry), f"{entry}: name the path, not a pattern"
        (index,) = [number for number, line in enumerate(lines) if line.strip() == f"- {entry}"]
        reason = lines[index - 1].strip()
        assert reason.startswith("# ") and len(reason) > 30, (
            f"{entry}: put a comment line directly above it that says why the scan cannot read it"
        )


def test_exclusions_inside_the_protected_trees_are_the_named_exceptions() -> None:
    for entry in _exclusions():
        parts = PurePosixPath(entry).parts
        if parts[0] in PROTECTED_TREES:
            assert entry in ALLOWED_INSIDE_PROTECTED_TREES, (
                f"{entry} would hide part of the {parts[0]} tree from the self-scan; if it must, "
                "name it in ALLOWED_INSIDE_PROTECTED_TREES with the reason"
            )


def _glob_excluded(entry: str, relative: str) -> bool:
    """The connector's glob test (`_excluded_file`) for an entry that names a path."""
    if "/" not in entry:
        return False
    path = PurePosixPath(relative)
    return path.match(entry) or path.match(entry.rstrip("/") + "/*")


def _skipped_paths() -> dict[str, list[str]]:
    """The paths the connector's walk skips for each exclusion, outermost match only.

    Mirrors `TreeWalker._excluded` in code/walk.py (a name without a separator matches a directory
    at any depth; anything else is matched as a right-anchored glob) and the default exclusions,
    so an exclusion that is stale or broader than it reads is found without a 40 second scan.
    """
    entries = _exclusions()
    skipped: dict[str, list[str]] = {entry: [] for entry in entries}
    for current, directories, files in os.walk(ROOT):
        folder = PurePosixPath(Path(current).relative_to(ROOT).as_posix())
        kept = []
        for directory in sorted(directories):
            if directory in DEFAULT_EXCLUDES:
                continue
            relative = (folder / directory).as_posix()
            hit = next(
                (e for e in entries if e == directory or _glob_excluded(e, relative)),
                None,
            )
            if hit is None:
                kept.append(directory)
            else:
                skipped[hit].append(relative)
        directories[:] = kept
        for file in sorted(files):
            relative = (folder / file).as_posix()
            hit = next((e for e in entries if _glob_excluded(e, relative)), None)
            if hit is not None:
                skipped[hit].append(relative)
    return skipped


def test_each_exclusion_skips_exactly_the_path_it_names() -> None:
    for entry, paths in _skipped_paths().items():
        if entry not in GENERATED:
            assert paths, f"{entry} matches nothing in this checkout; remove the stale exclusion"
        assert paths in ([], [entry]), (
            f"{entry} also skips {sorted(set(paths) - {entry})}; the scanner matches a name at any "
            "depth, so name a longer path that matches only the file or directory you mean"
        )


def test_generated_exclusions_are_ignored_by_git_and_hold_nothing_tracked() -> None:
    exclusions = _exclusions()
    ignored = _text(ROOT / ".gitignore").splitlines()
    for entry, ignore_line in GENERATED.items():
        assert entry in exclusions, f"{entry} is not excluded any more; remove it from GENERATED"
        assert ignore_line in ignored, f".gitignore no longer ignores {ignore_line}, the output of {entry}"
        if shutil.which("git") and (ROOT / ".git").exists():
            tracked = subprocess.run(
                ["git", "ls-files", "--", entry], cwd=ROOT, capture_output=True, text=True, check=True
            ).stdout.split()
            assert not tracked, f"{entry} holds tracked files {tracked[:3]}; excluding it would hide them"


def test_make_and_ci_run_the_same_self_scan_on_every_python() -> None:
    makefile = _text(ROOT / "Makefile")
    recipe = makefile.split("\nself-scan:", 1)[1].split("\n.PHONY", 1)[0]
    assert COMMAND in recipe
    (check,) = [line for line in makefile.splitlines() if line.startswith("check:")]
    assert "self-scan" in check.split("##", 1)[0].split(), "make check no longer runs the self-scan"

    workflow = yaml.safe_load(_text(ROOT / ".github" / "workflows" / "ci.yml"))
    (step,) = [s for s in workflow["jobs"]["test"]["steps"] if COMMAND in s.get("run", "")]
    # The step runs in every leg of the Python matrix and cannot be waved through.
    assert not {"if", "continue-on-error"} & set(step), "the self-scan step must always run and fail the job"
    assert "|| " not in step["run"] and "--fail-on" not in step["run"]


def test_documents_describe_the_self_scan_and_the_gates_of_make_check() -> None:
    for document in ("README.md", "docs/getting-started/quickstart.md", "docs/testing.md"):
        assert "make self-scan" in _text(ROOT / document), f"{document} no longer names make self-scan"
    assert "shadowscan.self-scan.yaml" in _text(ROOT / "examples" / "README.md")

    (check,) = [line for line in _text(ROOT / "Makefile").splitlines() if line.startswith("check:")]
    gates = check.split("##", 1)[0].removeprefix("check:").split()
    documented = re.search(
        r"^make check\s+# exactly: (.+)$", _text(ROOT / "docs" / "testing.md"), re.MULTILINE
    )
    assert documented is not None, "docs/testing.md no longer lists the gates of make check"
    assert documented.group(1).split() == gates
