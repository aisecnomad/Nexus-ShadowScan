"""The documents, tooling and metadata stay consistent with each other and the code.

`test_repository_policy.py` guards workflow privileges and issue-form structure.
This module covers the rest of the repository's self-consistency: every relative
Markdown link and heading anchor resolves, the community files GitHub and the
OpenSSF Scorecard look for exist, `CITATION.cff` matches `pyproject.toml`, the
CI matrices, `requires-python` and every documented interpreter range match the
classifiers, the Makefile and pre-commit hooks run what CI runs, every CodeQL
action step is pinned to the same release, the docs toolchain comes from its lock
everywhere, and documented counts, the README's demo output, CSV report markers,
the HTTP read deadline and the plugin execution default match the shipped code.
Run both modules with ``make policy``.
"""

from __future__ import annotations

import ast
import functools
import importlib.util
import inspect
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import textwrap
import tokenize
import tomllib
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from urllib.parse import unquote

import pytest
import yaml

from shadowscan.config import ScanConfig
from shadowscan.connectors import ConnectorContext, builtin_connector_names, get_connector_class
from shadowscan.connectors.cloud.gcp import AI_SERVICES as GCP_AI_SERVICES
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.common import MAX_PAGES
from shadowscan.connectors.endpoint.catalog import MODEL_STORES
from shadowscan.connectors.endpoint.runtime import EbpfConnector, HostConnector, OtelConnector
from shadowscan.coverage import DEFAULT_MAX_GAP_RATIO
from shadowscan.engine import DEFAULT_CONNECTOR_TIMEOUT, Engine
from shadowscan.models import ScanStats
from shadowscan.reporters.csv_ import _safe_cell
from shadowscan.utils import http

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
# GitHub runs both YAML spellings; test_repository_policy.py checks the glob.
WORKFLOWS = sorted(path for path in (GITHUB / "workflows").glob("*.y*ml") if path.is_file())
FORMS = sorted(path for path in (GITHUB / "ISSUE_TEMPLATE").glob("*.yml") if path.name != "config.yml")
ADVISORY_URL = "https://github.com/aisecnomad/Nexus-ShadowScan/security/advisories/new"

# Files GitHub's community profile and the OpenSSF Scorecard look for, plus the
# project's own governance set. Each must exist and carry content.
COMMUNITY_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "ROADMAP.md",
    "CODEOWNERS",
    "CITATION.cff",
    "AGENTS.md",
    ".editorconfig",
    ".gitattributes",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/dependabot.yml",
    ".github/labels.yml",
    "requirements.lock",
    "requirements-build.lock",
    "requirements-ci.lock",
    "requirements-docs.lock",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(_read(path))


@functools.cache
def _pyproject() -> dict[str, Any]:
    return tomllib.loads(_read(ROOT / "pyproject.toml"))


def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


# --- Markdown -----------------------------------------------------------------


# The ShadowBench estate's authored files: the fictional organization's repositories and home
# directories, each frozen by digest in FREEZE.json. Their Markdown is scan input written as that
# organization's own files, not this repository's documentation (repo-site's index.md links the
# shipping-faq.html its site generator would emit, which does not exist here), and correcting it
# would change a frozen file. Everything else under benchmarks/ is checked. That includes the run
# reports under results/, which are generated and committed with their run: they pass, so a failure
# there would mean that something a report links or names has moved.
_FROZEN_MARKDOWN = ROOT / "benchmarks" / "shadowbench" / "estate" / "artifacts"


def _markdown_files() -> list[Path]:
    files = sorted(ROOT.glob("*.md"))
    for folder in (".github", "archive", "benchmarks", "docs", "examples", "tools"):
        files.extend(sorted((ROOT / folder).rglob("*.md")))
    return [path for path in files if not path.is_relative_to(_FROZEN_MARKDOWN)]


def _benchmark_documents() -> list[Path]:
    return [path for path in _markdown_files() if path.is_relative_to(ROOT / "benchmarks")]


_FENCE = re.compile(r"^(`{3,}|~{3,})")


def _prose_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, line)`` for every line outside a fenced code block."""
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = _FENCE.match(line.lstrip())
        if match is not None:
            marker = match.group(1)[0]
            if fence is None:
                fence = marker
                continue
            if marker == fence:
                fence = None
                continue
        if fence is None:
            yield number, line


_SHELL_INFO = frozenset({"", "bash", "sh", "shell", "console"})


def _shell_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, command)`` for each line of a shell or unlabeled fenced block."""
    fence: str | None = None
    shell = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        match = _FENCE.match(stripped)
        if match is not None:
            marker = match.group(1)[0]
            if fence is None:
                fence, shell = marker, stripped[len(match.group(1)) :].strip().lower() in _SHELL_INFO
                continue
            if marker == fence:
                fence = None
                continue
        if fence is not None and shell:
            yield number, stripped.removeprefix("$ ")


_INLINE_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
_INLINE_CODE = re.compile(r"`[^`]*`")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _link_targets(text: str) -> Iterator[tuple[int, str]]:
    for number, line in _prose_lines(text):
        prose = _INLINE_CODE.sub("", line)
        for match in _INLINE_LINK.finditer(prose):
            yield number, match.group(1)
        reference = _REFERENCE_LINK.match(prose)
        if reference is not None:
            yield number, reference.group(1)


def _is_external(target: str) -> bool:
    return target.startswith("//") or _SCHEME.match(target) is not None


def _resolve(source: Path, target: str) -> tuple[Path, str | None]:
    path_part, _, anchor = target.partition("#")
    path_part = unquote(path_part)
    if not path_part:
        return source, anchor or None
    if path_part.startswith("/"):
        return (ROOT / path_part.lstrip("/")).resolve(), anchor or None
    return (source.parent / path_part).resolve(), anchor or None


_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_ATTR_ID = re.compile(r"\{\s*#([^\s}]+)\s*\}\s*$")
_MARKDOWN_LINK_TEXT = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def _github_slug(heading: str) -> str:
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


def _mkdocs_slug(heading: str) -> str:
    return re.sub(r"[-\s]+", "-", re.sub(r"[^\w\s-]", "", heading).strip().lower())


_SNIPPET = re.compile(r'^--8<-- "([^"]+)"$', re.MULTILINE)


@functools.cache
def _site_pages() -> frozenset[Path]:
    """Top-level documents the docs site includes as snippets; docs/ itself is rendered too."""
    return frozenset(
        (ROOT / name).resolve()
        for page in (ROOT / "docs").rglob("*.md")
        for name in _SNIPPET.findall(_read(page))
    )


@functools.cache
def _anchors(path: Path) -> frozenset[str]:
    """Heading anchors that every renderer of a Markdown file generates.

    GitHub renders every file. docs/ pages and the snippets the site includes are
    also rendered by MkDocs, so a linked anchor there must be one both generate:
    GitHub keeps "--" where MkDocs collapses it, they number repeated headings
    differently, and `{#id}` works on the site only (GitHub shows it as text).
    """
    on_site = path.resolve().is_relative_to((ROOT / "docs").resolve()) or path.resolve() in _site_pages()
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for _, line in _prose_lines(_read(path)):
        match = _HEADING.match(line)
        if match is None:
            continue
        heading = match.group(1)
        explicit = _ATTR_ID.search(heading)
        if explicit is not None:
            heading = heading[: explicit.start()]
        heading = _MARKDOWN_LINK_TEXT.sub(r"\1", heading)
        heading = heading.replace("`", "").replace("*", "").strip()
        slug = _github_slug(heading)
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        if not on_site:
            anchors.add(slug if count == 0 else f"{slug}-{count}")
        elif count == 0 and _mkdocs_slug(heading) == slug:
            anchors.add(slug)
    return frozenset(anchors)


@pytest.mark.parametrize("markdown", _markdown_files(), ids=_relative)
def test_relative_markdown_links_and_anchors_resolve(markdown: Path) -> None:
    problems: list[str] = []
    for number, target in _link_targets(_read(markdown)):
        if _is_external(target):
            continue
        resolved, anchor = _resolve(markdown, target)
        if not resolved.exists():
            problems.append(f"line {number}: {target} -> {resolved.relative_to(ROOT)} does not exist")
            continue
        if anchor and resolved.suffix == ".md" and anchor.lower() not in _anchors(resolved):
            problems.append(f"line {number}: {target} -> no heading produces #{anchor}")
    assert not problems, f"{_relative(markdown)}:\n  " + "\n  ".join(problems)


def test_markdown_checks_cover_benchmarks_but_not_the_frozen_estate() -> None:
    """Benchmark READMEs and run reports are documentation; the estate's authored files are scan input."""
    checked = {path.relative_to(ROOT).as_posix() for path in _markdown_files()}
    assert {
        "benchmarks/README.md",
        "benchmarks/shadowbench/README.md",
        "benchmarks/shadowbench/cases/README.md",
        "benchmarks/shadowbench/estate/README.md",
        "benchmarks/shadowbench/estate/results/2026-10-11/REPORT.md",
    } <= checked
    frozen = {path.relative_to(ROOT).as_posix() for path in _FROZEN_MARKDOWN.rglob("*.md")}
    assert frozen, "the estate's authored Markdown moved; point _FROZEN_MARKDOWN at it"
    assert not frozen & checked


_REPOSITORY_LINK = re.compile(
    r"https://github\.com/aisecnomad/Nexus-ShadowScan/(blob|tree)/main/([^#?]+)(?:#(.+))?"
)


# The repository was renamed from aisecnomad/Project-Nexus to aisecnomad/Nexus-ShadowScan so
# that its URL, the NexusShadowScan distribution and the brand match. These paths record
# history as it happened and keep the former name: retained reviews, frozen benchmark
# corpora, results and the harnesses that reproduce them, and GitHub's recorded ruleset
# responses. Released changelog entries are history too; the Unreleased section is not.
_FORMER_NAME_RECORDS = (
    "archive/",
    "benchmarks/",
    "tools/benchmark/",
    "tools/benchmark_realworld/",
    "tools/discovery_benchmark/",
    "tools/shadowbench/",
    ".github/rulesets/observed/",
)
_FORMER_NAME = re.compile(r"aisecnomad(?:/|%2F|\.github\.io/)Project-Nexus", re.IGNORECASE)
# Elsewhere the former name may appear only in these forms, which say that it is the
# former name: 0.1.2 was attested under it, the rename is described, and one dated
# observation keeps the request path it recorded. Each form is removed from the line
# before the check, so a stale link beside one is still caught.
_FORMER_SLUG = re.escape("aisecnomad/" + "Project-Nexus")  # split so this file passes its own check
_FORMER_NAME_FORMS = re.compile(
    "|".join(
        form.replace("SLUG", _FORMER_SLUG)
        for form in (
            r"gh attestation verify \S*-0\.1\.2-\S* --repo SLUG$",
            r"verify (?:it|0\.1\.2) with `--repo SLUG`",
            r"attested as `SLUG` before the rename",
            r"renamed from `?SLUG`? to",
            r"formerly `?SLUG`?(?![\w.%/-])",
            r"`GET /repos/SLUG/[^`]*` \(the former name\)",
            r'^FORMER_REPOSITORY = "SLUG"$',
        )
    )
)


def _names_former_repository(line: str) -> bool:
    return bool(_FORMER_NAME.search(_FORMER_NAME_FORMS.sub("", line.strip())))


_FIRST_RELEASED_SECTION = re.compile(r"^## \[?0\.", re.MULTILINE)


def test_live_files_name_the_current_repository() -> None:
    """Regression: links, badges, clone commands and policy checks follow the repository rename."""
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=60
    ).stdout.decode("utf-8")
    stale = []
    for name in filter(None, tracked.split("\0")):
        if name.startswith(_FORMER_NAME_RECORDS) or not (ROOT / name).is_file():
            continue
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if name in ("CHANGELOG.md", "docs/engineering-log.md"):
            # Dated logs: the released sections record the name the repository had then. The
            # changelog's headings follow Keep a Changelog (``## [0.1.2] - 2026-10-08``).
            released = _FIRST_RELEASED_SECTION.search(text)
            assert released is not None, f"{name} has no released section"
            text = text[: released.start()]
        stale.extend(
            f"{name}:{number}"
            for number, line in enumerate(text.splitlines(), start=1)
            if _names_former_repository(line)
        )
    assert not stale, "use aisecnomad/Nexus-ShadowScan:\n  " + "\n  ".join(stale)


def test_former_name_check_flags_unexplained_references() -> None:
    # Assembled from parts so that this test's own lines do not trip the check above.
    slug, pages = "aisecnomad/" + "Project-Nexus", "aisecnomad.github.io/" + "Project-Nexus"
    assert _FORMER_NAME.search(f"https://github.com/{slug.lower()}/blob/main/README.md")
    assert _FORMER_NAME.search(f"https://{pages}/")
    assert not _FORMER_NAME.search("https://github.com/aisecnomad/Nexus-ShadowScan")
    for explained in (
        f"gh attestation verify wheels/nexusshadowscan-0.1.2-py3-none-any.whl --repo {slug}",
        f"The 0.1.2 wheel was attested before the rename; verify it with `--repo {slug}`.",
        f"The repository was formerly `{slug}`; GitHub redirects the old links.",
        f"- The repository is renamed from `{slug}` to",
        f"`GET /repos/{slug}/rules/branches/main` (the former name) returned no active",
    ):
        assert not _names_former_repository(explained), explained
    for stale in (
        f"git clone https://github.com/{slug}.git",
        f'python -m pip install "git+https://github.com/{slug}.git@v0.1.2"',
        f"[![CI](https://github.com/{slug}/actions/workflows/ci.yml/badge.svg)] <!-- before renaming -->",
        f"Report at https://github.com/{slug}/security/advisories/new (formerly email)",
        "https://img.shields.io/badge/x?link=github.com%2F" + slug.replace("/", "%2F"),
        f"formerly `{slug}`; see https://github.com/{slug}/blob/main/SECURITY.md",
        f"gh pr create --repo {slug}",
        f"`git clone https://github.com/{slug}.git` (the former name)",
        f"It was formerly {slug}.git; clone it from there",
    ):
        assert _names_former_repository(stale), stale


@pytest.mark.parametrize("markdown", _markdown_files(), ids=_relative)
def test_absolute_repository_links_resolve_in_this_checkout(markdown: Path) -> None:
    """Links that must stay absolute (README on PyPI, the changelog on the docs site) still cannot rot."""
    problems: list[str] = []
    for number, target in _link_targets(_read(markdown)):
        match = _REPOSITORY_LINK.fullmatch(target)
        if match is None:
            continue
        kind, path, anchor = match.groups()
        resolved = ROOT / unquote(path)
        if not resolved.exists() or (kind == "tree") != resolved.is_dir():
            problems.append(f"line {number}: {target} -> no {kind} {path} in this checkout")
        elif anchor and resolved.suffix == ".md" and anchor.lower() not in _anchors(resolved):
            problems.append(f"line {number}: {target} -> no heading produces #{anchor}")
    assert not problems, f"{_relative(markdown)}:\n  " + "\n  ".join(problems)


def test_readme_links_work_on_the_package_index() -> None:
    """README.md is the PyPI project description, where a relative link resolves against pypi.org."""
    relative = [
        f"line {number}: {target}"
        for number, target in _link_targets(_read(ROOT / "README.md"))
        if not _is_external(target) and not target.startswith("#")
    ]
    assert not relative, "link the repository URL instead:\n  " + "\n  ".join(relative)
    assert _pyproject()["project"]["readme"] == "README.md"


# Root documents the site includes as snippets (CHANGELOG.md, SECURITY.md, GOVERNANCE.md), plus
# README.md, CONTRIBUTING.md and RELEASE_NOTES.md (which now points to docs/release-notes.md), which
# GitHub renders the same way.
_SITE_ROOT_DOCS = (
    "CHANGELOG.md",
    "RELEASE_NOTES.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "CONTRIBUTING.md",
    "README.md",
)
# One to six "#" followed by anything but a space or another "#": Markdown renders the line as a
# heading, which a wrapped reference such as "#132 and #133" at the start of a line never means.
_ACCIDENTAL_HEADING = re.compile(r"^#{1,6}[^# ]")


def _site_documents() -> list[Path]:
    return [*(ROOT / name for name in _SITE_ROOT_DOCS), *sorted((ROOT / "docs").rglob("*.md"))]


def _accidental_headings(text: str) -> list[int]:
    """Line numbers outside fenced code blocks that Markdown would render as a heading by accident."""
    return [number for number, line in _prose_lines(text) if _ACCIDENTAL_HEADING.match(line)]


def test_accidental_heading_check_ignores_code_blocks_and_real_headings() -> None:
    text = "# Title\n\n#123 and #124 were merged.\n\n```sh\n#!/bin/sh\n```\n\n## Section\n\n#######x\n  #5 indented\n"
    assert _accidental_headings(text) == [3]


# The benchmark READMEs and run reports are not on the site, but GitHub renders them, and the
# ShadowBench READMEs cite pull requests by number.
@pytest.mark.parametrize("markdown", [*_site_documents(), *_benchmark_documents()], ids=_relative)
def test_no_prose_line_starts_with_an_issue_number(markdown: Path) -> None:
    """A wrapped line that starts with ``#132`` renders as a heading on the docs site and on GitHub."""
    lines = _accidental_headings(_read(markdown))
    assert not lines, f"{_relative(markdown)}: re-wrap lines {lines} so they do not start with '#'"


def test_issue_form_links_reference_forms_that_exist() -> None:
    forms = {path.name for path in FORMS}
    for markdown in _markdown_files():
        for match in re.finditer(r"template=([\w.-]+\.yml)", _read(markdown)):
            assert match.group(1) in forms, f"{_relative(markdown)} links missing form {match.group(1)}"


class _MkDocsLoader(yaml.SafeLoader):
    """Reads mkdocs.yml, ignoring Material's ``!!python/name`` tags."""


_MkDocsLoader.add_multi_constructor("tag:yaml.org,2002:python/name:", lambda loader, suffix, node: None)


def _nav_pages(entries: Any) -> Iterator[str]:
    if isinstance(entries, str):
        yield entries
    elif isinstance(entries, list):
        for entry in entries:
            yield from _nav_pages(entry)
    elif isinstance(entries, dict):
        for value in entries.values():
            yield from _nav_pages(value)


def test_every_documentation_page_is_reachable_from_the_site_navigation() -> None:
    """A page missing from the nav is built but unreachable on the published site."""
    config = yaml.load(_read(ROOT / "mkdocs.yml"), Loader=_MkDocsLoader)  # a SafeLoader subclass
    listed = set(_nav_pages(config["nav"]))
    pages = {path.relative_to(ROOT / "docs").as_posix() for path in (ROOT / "docs").rglob("*.md")}
    assert not pages - listed, f"docs pages missing from the mkdocs nav: {sorted(pages - listed)}"
    assert not listed - pages, f"mkdocs nav entries without a page: {sorted(listed - pages)}"


# --- Community profile ---------------------------------------------------------


@pytest.mark.parametrize("name", COMMUNITY_FILES)
def test_community_file_exists_with_content(name: str) -> None:
    path = ROOT / name
    assert path.is_file(), f"{name} is missing"
    assert path.stat().st_size > 0, f"{name} is empty"


def test_security_policy_has_the_sections_reporters_expect() -> None:
    anchors = _anchors(ROOT / "SECURITY.md")
    for anchor in ("trust-boundary", "supported-versions", "reporting"):
        assert anchor in anchors, f"SECURITY.md lacks a '{anchor}' heading"
    assert ADVISORY_URL in _read(ROOT / "SECURITY.md")


@pytest.mark.parametrize(
    "name", ["SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "MAINTAINERS.md"]
)
def test_private_reporting_channel_is_reachable_from_every_entry_point(name: str) -> None:
    text = _read(ROOT / name)
    assert ADVISORY_URL in text or "SECURITY.md#reporting" in text, (
        f"{name} must link the private advisory form or the SECURITY.md reporting section"
    )


@pytest.mark.parametrize("name", ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "GOVERNANCE.md"])
def test_code_of_conduct_is_linked_from_entry_points(name: str) -> None:
    assert "CODE_OF_CONDUCT.md" in _read(ROOT / name), f"{name} must link the code of conduct"


def test_code_of_conduct_is_the_contributor_covenant_with_a_reporting_route() -> None:
    text = _read(ROOT / "CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in text
    assert "reporting-a-concern" in _anchors(ROOT / "CODE_OF_CONDUCT.md"), (
        "SUPPORT.md deep-links this heading"
    )
    assert ADVISORY_URL in text


def test_citation_matches_the_package_metadata() -> None:
    citation = _load_yaml(ROOT / "CITATION.cff")
    project = _pyproject()["project"]
    assert citation["version"] == project["version"]
    license = project["license"]
    assert citation["license"] == (license if isinstance(license, str) else license["text"])
    assert citation["repository-code"] == project["urls"]["Repository"]
    assert citation["url"] == project["urls"]["Documentation"]


# The word each one-line scope description uses for a discovery surface; a
# plural or a longer phrase ("LLM gateway logs", "running processes") matches.
SURFACE_WORDS = {
    "code": "code",
    "identity": "identity",
    "gateway": "gateway",
    "lowcode": "low-code",
    "saas": "saas",
    "cloud": "cloud",
    "endpoint": "endpoint",
    "network": "network",
    "runtime": "process",
}


def test_scope_descriptions_name_every_discovery_surface() -> None:
    from shadowscan import cli
    from shadowscan.connectors import base
    from shadowscan.models import ScanResult, Surface
    from shadowscan.reporters.html import render_html

    assert set(SURFACE_WORDS) == {surface.value for surface in Surface}, "name the new surface here"
    intro = re.search(r"It inspects \w+ surfaces: (.+?)\.\s", _read(ROOT / "README.md"), re.S)
    assert intro, "README should list the surfaces it inspects"
    header = re.search(r"<header>.*?</header>", render_html(ScanResult()), re.S)
    assert header
    descriptions = {
        "pyproject.toml description": _pyproject()["project"]["description"],
        "CITATION.cff abstract": _load_yaml(ROOT / "CITATION.cff")["abstract"],
        "README introduction": intro.group(1),
        "docs/index.md": _read(ROOT / "docs" / "index.md"),
        "shadowscan --help": cli.main.help or "",
        "HTML report header": header.group(0),
    }
    for where, text in descriptions.items():
        missing = [w for w in SURFACE_WORDS.values() if not re.search(rf"(?<![\w-]){w}", text, re.I)]
        assert not missing, f"{where} omits {missing}"
    missing = [s.value for s in Surface if not re.search(rf"\b{s.value}\b", base.__doc__ or "")]
    assert not missing, f"shadowscan/connectors/base.py docstring omits {missing}"


def test_codeowners_paths_exist() -> None:
    for line in _read(ROOT / "CODEOWNERS").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pattern = line.split()[0]
        if pattern != "*":
            assert (ROOT / pattern.strip("/")).exists(), f"CODEOWNERS names {pattern}, which does not exist"


# --- CI, tooling and supply-chain parity --------------------------------------


def _ci_run_lines() -> list[str]:
    lines: list[str] = []
    for job in (_load_yaml(GITHUB / "workflows" / "ci.yml").get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if isinstance(script, str):
                lines.extend(line.strip() for line in script.splitlines())
    return lines


def _first_tool_arguments(lines: list[str], tool: str) -> set[str]:
    for line in lines:
        if line.startswith(f"{tool} "):
            return set(line.split()[1:])
    raise AssertionError(f"no {tool} invocation found")


def test_ci_matrix_covers_every_classified_python_version() -> None:
    ci = _load_yaml(GITHUB / "workflows" / "ci.yml")
    matrix = {str(version) for version in ci["jobs"]["test"]["strategy"]["matrix"]["python"]}
    classified = {
        classifier.rsplit("::", 1)[1].strip()
        for classifier in _pyproject()["project"]["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", classifier)
    }
    assert matrix == classified, f"CI tests {sorted(matrix)} but pyproject classifies {sorted(classified)}"


def _classified_minors() -> set[int]:
    return {
        int(classifier.rsplit(".", 1)[1])
        for classifier in _pyproject()["project"]["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", classifier)
    }


def _ci_matrix_minors(job: str) -> set[int]:
    versions = _load_yaml(GITHUB / "workflows" / "ci.yml")["jobs"][job]["strategy"]["matrix"]["python"]
    return {int(str(version).split(".", 1)[1]) for version in versions}


def _versions(minors: set[int]) -> str:
    return ", ".join(f"3.{minor}" for minor in sorted(minors))


def test_requires_python_admits_exactly_the_classified_versions() -> None:
    requires = _pyproject()["project"]["requires-python"]
    bounds = re.fullmatch(r">=3\.(\d+),<3\.(\d+)", requires)
    assert bounds is not None, f"requires-python {requires!r} is not a >=3.N,<3.M range"
    admitted = set(range(int(bounds.group(1)), int(bounds.group(2))))
    assert admitted == _classified_minors(), (
        f"requires-python {requires} admits {_versions(admitted)} but pyproject classifies "
        f"{_versions(_classified_minors())}"
    )
    assert _ci_matrix_minors("test-macos") <= admitted, "the macOS job tests an interpreter pyproject refuses"


# Two or more CPython minor versions written as one list or range, however it is spelled:
# "3.11, 3.12 and 3.13", "3.11; 3.12; 3.13", "3.11 to 3.14", "3.11 up to and including 3.14",
# "3.11 - 3.14", "3.11 -- 3.14" (any dash or hyphen), "3.11...3.14", "3.11 up to Python 3.14",
# "python3.11–python3.14", "`3.11`–`3.14`", ">=3.11,<3.15", "≥3.11, <3.15", "<3.15,>=3.11",
# "3.11+ (tested through 3.14)", "3.11+ (tested on 3.14)", "macOS 3.11/3.14". A patch release such
# as 3.12.4 is not a minor version and ends the span, so "3.12.0 to 3.12.3" is not an interpreter
# claim; nor is a list whose last version is a possessive ("3.11, or Python 3.14's syntax" names
# what each interpreter does), although a range is ("3.11–3.13's standard library" still names
# 3.11 to 3.13); and an open "3.12+" with no upper bound describes behavior rather than a set.
_MINOR_VERSION = r"`?(?<![\d.])3\.\d+(?!\.?\d)`?"
# A later version of a span, which may also follow an ellipsis.
_LATER_MINOR_VERSION = r"`?(?:(?<![\d.])|(?<=\.\.))3\.\d+(?!\.?\d)`?"
_LIST_SEPARATOR = r" ?, ?(?:(?:and|or|&) )?| ?; ?| (?:and|or|&|plus) | ?/ ?"
_UPPER_BOUND = (
    r"(?:[A-Za-z-]+ ){0,3}?"
    r"(?:to|through|thru|up to|(?:tested|validated|verified|checked) (?:on|with|against)) "
)
_DASHES = "-‐‑‒–—―−"
_RANGE_SEPARATOR = (
    rf" ?(?:--|[{_DASHES}]) ?| ?(?:\.\.\.?|…) ?| (?:to|through|thru|until|up to)(?: and including)? "
    rf"|\+? (?:and|or) (?:later|newer|above),? \(?{_UPPER_BOUND}|\+ ?[(,]? ?{_UPPER_BOUND}"
)
_SPECIFIER = (
    r"(?:>=|≥) ?`?3\.\d+`? ?, ?(?:<=?|≤) ?`?3\.\d+`?"
    r"|(?:<=?|≤) ?`?3\.\d+`? ?, ?(?:>=|≥) ?`?3\.\d+`?"
)
_INTERPRETER_SPAN = re.compile(
    rf"{_SPECIFIER}|{_MINOR_VERSION}"
    rf"(?:(?:{_LIST_SEPARATOR}|{_RANGE_SEPARATOR})(?:C?[Pp]ython ?)?{_LATER_MINOR_VERSION})+"
)
_SPECIFIER_BOUND = re.compile(r"([<>]=?|[≤≥]) ?`?3\.(\d+)")
_RANGE_WORDS = re.compile(rf"[{_DASHES}+…]|\.\.|\b(?:to|through|thru|until|later|newer|above)\b")
_POSSESSIVE = re.compile(r"['’]s\b")
# A span describes the macOS CI matrix only when macOS alone is the platform its clause names last
# before it ("macOS 3.11/3.14", "on macOS for 3.11 and 3.14") and the clause is about CI. "Linux and
# macOS 3.11-3.14" or "on macOS, ShadowScan supports 3.11 to 3.14" state the supported set.
_CLAUSE_BREAK = re.compile(r"[;!?]|\.(?= )")
_PLATFORM = re.compile(r"\b(?:Linux|macOS|Ubuntu|Windows|WSL)\b")
_JOINED_PLATFORM = re.compile(r"\b(?:Linux|Ubuntu|Windows|WSL) ?(?:,|/|&|and|or) ?$")
_CI_WORDS = re.compile(r"\b(?:CI|jobs?|runners?|matrix|workflows?|legs?|tests?|tested)\b")
# Spans that record an earlier interpreter set on purpose, and why.
_DATED_INTERPRETER_SPANS = {
    ("docs/assurance-results.md", "3.11/3.12"): "the CI matrix when that dated result was recorded",
    ("README.md", "3.11–3.13"): "the published PyPI 0.1.2 release, whose metadata excludes Python 3.14",
    ("docs/getting-started/install.md", "3.11–3.13"): "the published PyPI 0.1.2 release, not current source",
}
# The lock headers state the interpreters each lock is validated on; docs/production.md asks for
# that comment to be kept when a lock is regenerated.
_LOCK_HEADERS = ("requirements.lock", "requirements-ci.lock", "requirements-ci-constraints.txt")


def _is_specifier(span: str) -> bool:
    return span[0] in "<>≤≥"


def _span_minors(span: str) -> set[int]:
    if _is_specifier(span):
        lower = upper = 0
        for operator, minor in _SPECIFIER_BOUND.findall(span):
            if operator in (">=", "≥"):
                lower = int(minor)
            else:
                upper = int(minor) + (operator != "<")
        return set(range(lower, upper))
    parts = re.split(r"3\.(\d+)", span)
    minors = [int(part) for part in parts[1::2]]
    covered = {minors[0]}
    for previous, separator, current in zip(minors[:-1], parts[2:-1:2], minors[1:], strict=True):
        covered.update(range(previous, current + 1) if _RANGE_WORDS.search(separator) else {current})
    return covered


def _describes_macos_ci(paragraph: str, match: re.Match[str]) -> bool:
    before = _CLAUSE_BREAK.split(paragraph[: match.start()])[-1]
    after = _CLAUSE_BREAK.split(paragraph[match.end() :])[0]
    platforms = list(_PLATFORM.finditer(before))
    if not platforms or platforms[-1].group(0) != "macOS":
        return False
    if _JOINED_PLATFORM.search(before[: platforms[-1].start()]):
        return False
    return _CI_WORDS.search(before + after) is not None


def _lists_possessives(paragraph: str, match: re.Match[str]) -> bool:
    """Whether the span ``match`` is a list whose last version is a possessive ("3.11, or
    Python 3.14's syntax"): it names what each interpreter does, not a supported set. A
    range whose upper bound is a possessive ("3.11–3.13's standard library") is not one."""
    span = match.group(0)
    if _is_specifier(span) or not _POSSESSIVE.match(paragraph, match.end()):
        return False
    last_separator = re.split(r"3\.\d+", span)[-2]
    return not _RANGE_WORDS.search(last_separator)


def _interpreter_spans(paragraph: str) -> list[tuple[str, bool]]:
    """``(span, about_macos_ci)`` for every interpreter span in one whitespace-normalized paragraph."""
    return [
        (match.group(0), _describes_macos_ci(paragraph, match))
        for match in _INTERPRETER_SPAN.finditer(paragraph)
        if not _lists_possessives(paragraph, match)
    ]


def _comment_header(path: Path) -> str:
    """The comment lines a requirements file starts with, joined into one paragraph."""
    lines = itertools.takewhile(lambda line: line.startswith("#"), _read(path).splitlines())
    return " ".join(" ".join(line.lstrip("#").split()) for line in lines)


def _package_strings(path: Path) -> str:
    """The string literals a package module holds (messages, help text, docstrings), one per paragraph."""
    tree = ast.parse(_read(path), filename=str(path))
    strings = (
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )
    return "\n\n".join(strings)


def _interpreter_claims() -> Iterator[tuple[str, str, bool]]:
    """``(document, span, about_macos)`` for every interpreter span a current document or package
    string states."""
    texts = [(_relative(path), _current_text(path)) for path in _current_docs()]
    texts += [(name, _comment_header(ROOT / name)) for name in _LOCK_HEADERS]
    texts += [
        (_relative(path), _package_strings(path)) for path in sorted((ROOT / "shadowscan").rglob("*.py"))
    ]
    for name, text in texts:
        for paragraph in re.split(r"\n[ \t]*\n", text):
            paragraph = " ".join(paragraph.split())
            for span, macos in _interpreter_spans(paragraph):
                yield name, span, macos


def test_documented_interpreter_ranges_match_the_classifiers_and_ci() -> None:
    """Every stated set of supported or CI-tested Pythons is the one pyproject and ci.yml declare.

    A span tied to macOS alone in a clause about CI describes the macOS job's matrix. Any other span
    describes what is supported and what the Linux job tests, which the matrix test above keeps
    equal to the classifiers. Adding 3.14 to pyproject and CI left the rollout guide, the testing guide and the
    lock headers promising 3.11 to 3.13 and macOS 3.11/3.13, and the Windows refusal message
    still names 3.11-3.13; package string literals are read as well as documents.
    """
    expected = {False: _classified_minors(), True: _ci_matrix_minors("test-macos")}
    claims = list(_interpreter_claims())
    stale = [
        f"{name}: {span!r} names {_versions(_span_minors(span))}, expected {_versions(expected[macos])}"
        + (" (macOS CI)" if macos else "")
        for name, span, macos in claims
        if (name, span) not in _DATED_INTERPRETER_SPANS and _span_minors(span) != expected[macos]
    ]
    assert not stale, "interpreter ranges disagree with pyproject.toml and ci.yml:\n" + "\n".join(stale)
    stating = {name for name, _, _ in claims}
    required = {
        "README.md",
        "docs/testing.md",
        "docs/production.md",
        *_LOCK_HEADERS[:2],
        "shadowscan/utils/platform.py",
    }
    assert required <= stating, f"{sorted(required - stating)} no longer state the interpreters they cover"
    assert any(macos for _, _, macos in claims), "a document should state the macOS CI interpreters"
    unused = set(_DATED_INTERPRETER_SPANS) - {(name, span) for name, span, _ in claims}
    assert not unused, f"stale dated interpreter spans: {sorted(unused)}"


@pytest.mark.parametrize(
    ("paragraph", "expected"),
    [
        ("CPython 3.11 – 3.13 on Linux", [({11, 12, 13}, False)]),
        ("Python 3.11 - 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11—3.13", [({11, 12, 13}, False)]),
        ("Python 3.11-3.14", [({11, 12, 13, 14}, False)]),
        ("Python 3.11 up to 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11 through Python 3.13", [({11, 12, 13}, False)]),
        ("Python `3.11`–`3.13`", [({11, 12, 13}, False)]),
        ("requires-python >=3.11,<3.14", [({11, 12, 13}, False)]),
        ("requires-python >=3.11, <=3.13", [({11, 12, 13}, False)]),
        ("Python 3.11, 3.12 and 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11, 3.12, and 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11 & 3.13", [({11, 13}, False)]),
        ("Python 3.11 or 3.13", [({11, 13}, False)]),
        ("Python 3.11 and later (tested through 3.13)", [({11, 12, 13}, False)]),
        ("Python 3.11+ (tested through 3.13)", [({11, 12, 13}, False)]),
        ("Python 3.11+, validated up to 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11+ (tested on 3.13)", [({11, 12, 13}, False)]),
        ("Python 3.11+ (tested with 3.13)", [({11, 12, 13}, False)]),
        ("Python 3.11; 3.12; 3.13", [({11, 12, 13}, False)]),
        ("from Python 3.11 up to and including 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11 -- 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11 ‐ 3.13", [({11, 12, 13}, False)]),
        ("Python 3.11−3.13", [({11, 12, 13}, False)]),
        ("Python 3.11...3.13", [({11, 12, 13}, False)]),
        ("Python 3.11…3.13", [({11, 12, 13}, False)]),
        ("python3.11–python3.13", [({11, 12, 13}, False)]),
        ("Python ≥3.11, <3.14", [({11, 12, 13}, False)]),
        ("Python ≥ 3.11, ≤ 3.13", [({11, 12, 13}, False)]),
        ("Python <3.14,>=3.11", [({11, 12, 13}, False)]),
        ("Python <=3.13, >=3.11", [({11, 12, 13}, False)]),
        ("Python 3.11–3.13's standard library", [({11, 12, 13}, False)]),
        ("Python 3.11–3.13’s standard library", [({11, 12, 13}, False)]),
        ("Python 3.11 through 3.13's tokenizer", [({11, 12, 13}, False)]),
        ("Python 3.11, 3.12 and 3.13's tokenizers", []),
        ("Python 3.11's tokenizer and 3.13's", []),
        ("macOS runners use Python 3.11 – 3.13", [({11, 12, 13}, True)]),
        ("CI runs on macOS for 3.11 and 3.14", [({11, 14}, True)]),
        ("The macOS 3.11 and 3.14 CI jobs install the locks", [({11, 14}, True)]),
        (
            "The workflow covers Linux 3.11–3.14 and macOS 3.11/3.14 for lint, types and tests",
            [({11, 12, 13, 14}, False), ({11, 14}, True)],
        ),
        ("ShadowScan supports Linux and macOS 3.11-3.14", [({11, 12, 13, 14}, False)]),
        ("On macOS, ShadowScan supports 3.11 to 3.14", [({11, 12, 13, 14}, False)]),
        (
            "CI tests macOS 3.11/3.14. ShadowScan supports 3.11 to 3.14",
            [({11, 14}, True), ({11, 12, 13, 14}, False)],
        ),
        ("Use CPython 3.12.4 or later rather than 3.12.0 to 3.12.3", []),
        ("Python 3.12+ tokenizers stop at 200 levels and 3.11 has no limit", []),
        ("SARIF 2.1.0, 3.11.6", []),
        ("a `type` statement on Python 3.11, or Python 3.14's `except A, B:` on 3.13", []),
        ("Python 3.11 is the minimum", []),
    ],
)
def test_interpreter_span_matcher_reads_ordinary_spellings(
    paragraph: str, expected: list[tuple[set[int], bool]]
) -> None:
    """The range check above is only as good as the matcher: each spelling here once passed it."""
    assert [(_span_minors(span), macos) for span, macos in _interpreter_spans(paragraph)] == expected


def test_distribution_rename_preserves_cli_and_plugin_contract() -> None:
    project = _pyproject()["project"]
    assert project["name"] == "NexusShadowScan"
    assert project["scripts"] == {"shadowscan": "shadowscan.cli:main"}
    assert "shadowscan.connectors" in project["entry-points"]
    assert project["optional-dependencies"]["all"] == [f"{project['name']}[cloud,dev,docs]"]
    for path in (
        ROOT / "docs/getting-started/install.md",
        ROOT / "examples/github-action-code-scan.yml",
        ROOT / "Makefile",
        GITHUB / "workflows/ci.yml",
        GITHUB / "workflows/release.yml",
    ):
        text = _read(path)
        assert "nexusshadowscan-*.whl" in text
        assert "/shadowscan-*.whl" not in text


def test_makefile_lint_and_typecheck_paths_match_ci() -> None:
    ci = _ci_run_lines()
    makefile = [line.strip() for line in _read(ROOT / "Makefile").splitlines()]
    assert _first_tool_arguments(makefile, "mypy") == _first_tool_arguments(ci, "mypy"), (
        "make typecheck drifted from CI"
    )
    ci_ruff = {arg for arg in _first_tool_arguments(ci, "ruff") if arg != "check"}
    make_ruff = {arg for arg in _first_tool_arguments(makefile, "ruff") if arg != "check"}
    assert make_ruff == ci_ruff, "make lint drifted from CI"


@pytest.mark.parametrize("target", ["wheel-validate", "coverage-gate"])
@pytest.mark.parametrize("fails", [False, True])
def test_make_validation_uses_private_temporary_paths_and_always_cleans_up(
    tmp_path: Path, target: str, fails: bool
) -> None:
    """Execute the actual recipe while stubbing costly package/coverage tools."""
    make = shutil.which("make")
    assert make is not None
    source = tmp_path / "checkout"
    source.mkdir()
    shutil.copyfile(ROOT / "Makefile", source / "Makefile")
    (source / "dist").mkdir()
    (source / "dist/nexusshadowscan-0.1.1-py3-none-any.whl").touch()
    scratch = tmp_path / "temporary files"
    scratch.mkdir()
    # Another run's directory must remain untouched, even when validation fails.
    previous = scratch / "shadowscan-wheel-test"
    previous.mkdir()
    sentinel = previous / "retain"
    sentinel.write_text("another developer's environment", encoding="utf-8")
    binary = tmp_path / "bin"
    binary.mkdir()
    shim = binary / "python"
    shim.write_text(
        textwrap.dedent("""\
            #!/bin/bash
            set -euo pipefail
            if [ "${1:-}" = -m ] && [ "${2:-}" = venv ]; then
                printf '%s\\n' "$3" >> "$TOOL_LOG"
                mkdir -p "$3/bin"
                cp "$0" "$3/bin/python"
                cp "$0" "$3/bin/shadowscan"
            elif [ "${2:-}" = coverage ]; then
                printf '%s\\n' "$5" >> "$TOOL_LOG"
                printf '{}\\n' > "$5"
            fi
            if [ "${2:-}" = "$FAIL_MODULE" ]; then exit 9; fi
            """),
        encoding="utf-8",
    )
    shim.chmod(0o700)
    log = tmp_path / "tool.log"
    module = "shadowscan.signatures.validate" if target == "wheel-validate" else "tools.coverage_gate"
    result = subprocess.run(
        [make, "--no-print-directory", "-o", "build", target],
        cwd=source,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(scratch),
            "TOOL_LOG": str(log),
            "FAIL_MODULE": module if fails else "never",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode != 0) is fails, result.stdout + result.stderr
    paths = [Path(path) for path in log.read_text(encoding="utf-8").splitlines()]
    assert len(paths) == 1
    # The wheel recipe builds its environment inside a private directory; the
    # coverage recipe writes a private file.
    private = paths[0].parent if target == "wheel-validate" else paths[0]
    assert private.parent == scratch
    assert private != previous
    assert not private.exists(), "temporary validation artifacts survive completion"
    assert sentinel.read_text(encoding="utf-8") == "another developer's environment"


def test_make_wheel_validation_rejects_stale_multiple_wheels(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    shutil.copyfile(ROOT / "Makefile", tmp_path / "Makefile")
    wheels = tmp_path / "dist"
    wheels.mkdir()
    for version in ("0.1.0", "0.1.1"):
        (wheels / f"nexusshadowscan-{version}-py3-none-any.whl").touch()
    result = subprocess.run(
        [make, "--no-print-directory", "-o", "build", "wheel-validate"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "requires exactly one scanner wheel" in result.stderr


def test_makefile_evaluates_the_same_corpora_as_ci() -> None:
    ci_corpora = set(re.findall(r"--corpus (\S+)", "\n".join(_ci_run_lines())))
    make_corpora = set(re.findall(r"--corpus (\S+)", _read(ROOT / "Makefile")))
    assert make_corpora == ci_corpora, (
        f"make evaluate runs {sorted(make_corpora)} but CI runs {sorted(ci_corpora)}"
    )
    for corpus in ci_corpora:
        assert (ROOT / corpus).is_file(), f"CI references a missing corpus {corpus}"


def _lock_audit_loop(text: str) -> str:
    """The `for lock in ...; do pip-audit ...; done` loop, without shell and make syntax."""
    flat = " ".join(text.replace("\\\n", " ").replace("$$", "$").replace(";", " ").split())
    match = re.search(r"for lock in .*? done", flat)
    assert match is not None, "no lock audit loop found"
    return match.group()


def test_make_audit_checks_the_environment_and_every_lock_like_ci() -> None:
    """`make check` must not pass while CI's audit of the hash locks fails."""
    makefile = _read(ROOT / "Makefile")
    recipe = makefile.split("\naudit:", 1)[1].split("\n.PHONY", 1)[0]
    ci_script = "\n".join(_ci_run_lines())
    for command in ("pip-audit --skip-editable --progress-spinner off",):
        assert command in recipe and command in ci_script
    assert _lock_audit_loop(recipe) == _lock_audit_loop(ci_script)
    locks = re.search(r"for lock in (.*?) do", _lock_audit_loop(recipe))
    assert locks is not None
    assert set(locks.group(1).split()) == {path.name for path in ROOT.glob("requirements*.lock")}
    assert "set -e; for lock in" in recipe, "the first failing lock must fail make audit"


def test_changelog_has_no_relative_links() -> None:
    """The docs site includes CHANGELOG.md from docs/changelog.md, so a relative link breaks one rendering."""
    prose = re.sub(r"`[^`\n]*`", "", _read(ROOT / "CHANGELOG.md"))  # code spans show link syntax, not links
    links = re.findall(r"\]\((?!https?://|mailto:|#)([^)\s]+)\)", prose)
    assert not links, f"name the file in a code span instead of linking it: {sorted(set(links))}"


def test_make_secrets_runs_the_ci_credential_check_and_is_part_of_make_check() -> None:
    """The credential hook only protects a commit if the local gate runs what CI runs."""
    makefile = _read(ROOT / "Makefile")
    command = "git ls-files -z | xargs -0 python tools/check_secrets.py"
    recipe = makefile.split("\nsecrets:", 1)[1].split("\n.PHONY", 1)[0]
    assert command in recipe
    assert command in "\n".join(_ci_run_lines())
    check = re.search(r"^check:(.*?)##", makefile, re.M)
    assert check is not None and "secrets" in check.group(1).split()


@pytest.mark.parametrize(
    ("target", "command"),
    [
        ("complexity", "python -m tools.complexity_gate"),
        ("ocsf-schema", "python -m tools.ocsf_schema --check"),
    ],
)
def test_make_check_runs_the_tool_gates_ci_runs(target: str, command: str) -> None:
    """CI runs these before ruff and pytest, so a local `make check` that skipped them passed a red build."""
    assert command in _ci_run_lines()
    makefile = _read(ROOT / "Makefile")
    recipe = makefile.split(f"\n{target}:", 1)[1].split("\n.PHONY", 1)[0]
    assert f"\t{command}\n" in recipe
    for gate in ("check", "check-fast"):
        prerequisites = re.search(rf"^{gate}:(.*?)##", makefile, re.M)
        assert prerequisites is not None and target in prerequisites.group(1).split(), gate


def test_pre_commit_hooks_are_immutable_and_match_ci_versions() -> None:
    config_text = _read(ROOT / ".pre-commit-config.yaml")
    revisions = {
        match.group("name"): (match.group("sha"), match.group("version"))
        for match in re.finditer(
            r"^  - repo: https://github\.com/[^/]+/(?P<name>[\w-]+)\n"
            r"    rev: (?P<sha>[0-9a-f]{40}) # v(?P<version>\S+)$",
            config_text,
            re.MULTILINE,
        )
    }
    assert {"pre-commit-hooks", "ruff-pre-commit", "mirrors-mypy"} <= revisions.keys()
    assert all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha, _ in revisions.values())
    constraints = dict(
        re.findall(
            r"^([A-Za-z0-9_.-]+)==(\S+)$", _read(ROOT / "requirements-ci-constraints.txt"), re.MULTILINE
        )
    )
    assert revisions["ruff-pre-commit"][1] == constraints["ruff"], (
        "pre-commit ruff version differs from the CI pin"
    )
    assert revisions["mirrors-mypy"][1] == constraints["mypy"], (
        "pre-commit mypy version differs from the CI pin"
    )
    for package in ("types-PyYAML", "types-requests"):
        pin = f"{package}=={constraints[package]}"
        assert pin in config_text, f"pre-commit additional dependency is not pinned: {package}"
    runtime = {
        name.lower(): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==(\S+)", _read(ROOT / "requirements.lock"), re.MULTILINE
        )
    }
    # The typed runtime libraries the checked packages import: without them the
    # hook sees Any where CI sees the real types.
    for package in ("click", "PyJWT", "rich", "urllib3"):
        assert f"{package}=={runtime[package.lower()]}" in config_text, (
            f"pre-commit mypy must type-check against the locked {package} version"
        )
    hook = next(
        hook
        for repo in yaml.safe_load(config_text)["repos"]
        for hook in repo["hooks"]
        if hook["id"] == "mypy" and "additional_dependencies" in hook
    )
    assert hook["args"] == [], "the mypy hook must not ignore missing imports; CI does not"


def test_docs_toolchain_is_hash_locked_everywhere_it_is_installed() -> None:
    lock = _read(ROOT / "requirements-docs.lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    assert pins, "requirements-docs.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(pins), "every docs dependency needs at least one hash"
    locked = {name.lower(): version for name, version in pins}
    for requirement in _pyproject()["project"]["optional-dependencies"]["docs"]:
        name, _, floor = requirement.partition(">=")
        # The lock pins the distribution; an extra ("mkdocstrings[python]")
        # names its handler, locked under its own name.
        name = name.partition("[")[0]
        assert locked.get(name.lower()) == floor, f"{requirement} and requirements-docs.lock disagree"
    install = "--require-hashes --only-binary=:all: -r requirements-docs.lock"
    for workflow in ("docs.yml", "ci.yml"):
        assert install in _read(GITHUB / "workflows" / workflow), (
            f"{workflow} must install docs tools from the lock"
        )
    assert install in _read(ROOT / "Makefile"), "make docs must install docs tools from the lock"
    for workflow in WORKFLOWS:
        assert "mkdocs-material==" not in _read(workflow), f"{workflow.name} pins mkdocs outside the lock"


def test_dockerfile_stages_keep_the_image_digest_and_python_pins_in_sync() -> None:
    dockerfile = _read(ROOT / "Dockerfile")
    from_lines = [line for line in dockerfile.splitlines() if re.match(r"^\s*FROM\s+", line, re.IGNORECASE)]
    assert len(from_lines) == 2, f"Dockerfile FROM drift: expected 2 stages, found {len(from_lines)}"
    images = [re.match(r"^\s*FROM\s+(\S+)", line, re.IGNORECASE).group(1) for line in from_lines]
    assert all(re.search(r"@sha256:[0-9a-f]{64}$", image) for image in images), (
        "Dockerfile base image drift: both FROM stages must use an image@sha256 digest"
    )
    assert images[0] == images[1], "Dockerfile base image digest drift between build and runtime stages"

    stages = re.split(r"(?im)(?=^FROM\s+)", dockerfile)
    stages = [stage for stage in stages if re.match(r"(?im)^FROM\s+", stage)]
    pin_pattern = re.compile(r"\b(python-3\.12(?:-base)?)=([^\s\\]+)")
    stage_pins: list[dict[str, set[str]]] = []
    for stage in stages:
        pins: dict[str, set[str]] = {}
        for line in stage.splitlines():
            if "apk add" not in line:
                continue
            for package, revision in pin_pattern.findall(line):
                pins.setdefault(package, set()).add(revision)
        stage_pins.append(pins)
    for package in ("python-3.12", "python-3.12-base"):
        build_revisions = stage_pins[0].get(package, set())
        runtime_revisions = stage_pins[1].get(package, set())
        assert build_revisions, f"Dockerfile {package} pin is missing from the build stage"
        assert runtime_revisions, f"Dockerfile {package} pin is missing from the runtime stage"
        assert len(build_revisions) == len(runtime_revisions) == 1, (
            f"Dockerfile {package} pin drift: each stage must use exactly one revision"
        )
        assert build_revisions == runtime_revisions, (
            f"Dockerfile {package} revision drift: build={sorted(build_revisions)}, "
            f"runtime={sorted(runtime_revisions)}"
        )


@pytest.mark.parametrize(
    "left,right",
    tuple(
        itertools.combinations(
            (
                "requirements.lock",
                "requirements-build.lock",
                "requirements-ci.lock",
                "requirements-docs.lock",
            ),
            2,
        )
    ),
)
def test_combined_toolchain_locks_agree_on_shared_versions(left: str, right: str) -> None:
    # make install and CI combine these locks. Independently valid locks can
    # otherwise make the documented hash-locked install impossible to resolve.
    locks = []
    for filename in (left, right):
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", _read(ROOT / filename), re.MULTILINE)
        locks.append({re.sub(r"[-_.]+", "-", name).lower(): version for name, version in pins})
    for package in sorted(locks[0].keys() & locks[1].keys()):
        assert locks[0][package] == locks[1][package], f"{package}: {left} and {right} have conflicting pins"


def test_ci_toolchain_is_exactly_pinned_and_hash_locked_everywhere() -> None:
    lock = _read(ROOT / "requirements-ci.lock")
    locked = {
        name.lower().replace("_", "-").replace(".", "-"): version
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    }
    assert locked, "requirements-ci.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(locked), "every CI dependency needs at least one hash"
    constraints = {
        name.lower().replace("_", "-").replace(".", "-"): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s;]+)(?:\s*;.*)?$",
            _read(ROOT / "requirements-ci-constraints.txt"),
            re.MULTILINE,
        )
    }
    assert constraints.items() <= locked.items(), "CI lock drifted from its reviewed direct constraints"
    # The universal resolution may only emit versions that come from a reviewed input:
    # this file, the runtime lock or the build lock (see the constraints header).
    reviewed = set(constraints)
    for other in ("requirements.lock", "requirements-build.lock"):
        reviewed |= {
            name.lower().replace("_", "-").replace(".", "-")
            for name, _ in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", _read(ROOT / other), re.MULTILINE)
        }
    unreviewed = sorted(set(locked) - reviewed)
    assert not unreviewed, f"requirements-ci.lock pins packages that no reviewed input names: {unreviewed}"
    for requirement in (
        _pyproject()["project"]["dependencies"] + _pyproject()["project"]["optional-dependencies"]["dev"]
    ):
        name = re.split(r"[<>=!\[; ]", requirement, maxsplit=1)[0]
        normalized = name.lower().replace("_", "-").replace(".", "-")
        assert normalized in locked, f"CI lock omits direct requirement {requirement}"
    install = "--require-hashes --only-binary=:all: -r requirements-ci.lock"
    assert install in _read(ROOT / "Makefile")
    assert install in _read(GITHUB / "workflows" / "ci.yml")
    assert "-r requirements-ci.lock" in _read(GITHUB / "workflows" / "release.yml")


def test_every_suite_environment_installs_the_build_frontend_lock() -> None:
    # Release evidence records the version of the build frontend, which only
    # requirements-build.lock provides. A test job or documented environment
    # without it fails tests/test_release_evidence.py.
    jobs = _load_yaml(GITHUB / "workflows" / "ci.yml")["jobs"]
    expected = ["requirements-build.lock", "requirements-ci.lock", "requirements.lock"]
    for name in ("test", "test-macos"):
        (install,) = [
            step["run"]
            for step in jobs[name]["steps"]
            if "--require-hashes" in step.get("run", "") and "-r requirements-ci.lock" in step["run"]
        ]
        assert sorted(re.findall(r"-r (requirements[\w-]*\.lock)", install)) == expected, name
    makefile = _read(ROOT / "Makefile")
    for target in ("install", "install-dev"):
        (recipe,) = re.findall(rf"^{target}:.*\n((?:\t.*\n)+)", makefile, re.MULTILINE)
        assert "-r requirements-build.lock" in recipe, target
    gates = _read(ROOT / "CONTRIBUTING.md").split("The same gates as individual commands:", 1)[1]
    # The documented gates start from make install, whose recipe is checked above.
    assert re.search(r"^make install$", gates.split("```", 2)[1], re.MULTILINE)
    assert "`requirements-build.lock`" in _read(ROOT / "docs" / "testing.md").split("## ", 2)[1]


_USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^#\s]+)\s*(?P<comment>#.*)?$")
_PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@(?P<sha>[0-9a-f]{40})$")


@pytest.mark.parametrize("example", sorted((ROOT / "examples").glob("*.yml")), ids=lambda path: path.name)
def test_example_workflows_pin_actions_to_commit_shas(example: Path) -> None:
    """Consumer examples are copied verbatim, so every action they use is pinned like the workflows."""
    problems: list[str] = []
    for number, line in enumerate(_read(example).splitlines(), start=1):
        match = _USES_LINE.match(line)
        if match is None:
            continue
        ref = match.group("ref").strip("'\"")
        if not _PINNED.match(ref):
            problems.append(f"line {number}: {ref} is not pinned to a 40-character commit SHA")
        if not re.search(r"#\s*v?\d", match.group("comment") or ""):
            problems.append(f"line {number}: {ref} needs a version comment")
    assert not problems, f"{_relative(example)}:\n  " + "\n  ".join(problems)


def test_example_action_pins_match_the_repository_workflows() -> None:
    """An action pinned in both places must point at the same commit."""

    def pins(paths):
        found: dict[str, set[str]] = {}
        for path in paths:
            for line in _read(path).splitlines():
                match = _USES_LINE.match(line)
                if match is None:
                    continue
                name, _, sha = match.group("ref").partition("@")
                found.setdefault(name, set()).add(sha)
        return found

    repository = pins(WORKFLOWS)
    for name, shas in pins(sorted((ROOT / "examples").glob("*.yml"))).items():
        if name in repository:
            assert shas <= repository[name], (
                f"examples pin {name} to {sorted(shas)} but workflows use {sorted(repository[name])}"
            )


def test_dependabot_moves_the_example_action_pins_with_the_workflows() -> None:
    """One grouped update covers both, so the pin-equality test above does not fail every bump."""
    updates = _load_yaml(GITHUB / "dependabot.yml")["updates"]
    (actions,) = [update for update in updates if update["package-ecosystem"] == "github-actions"]
    assert {"/", "/examples"} <= set(actions.get("directories") or [actions.get("directory")])
    assert any(group.get("patterns") == ["*"] for group in actions["groups"].values())


def test_example_workflow_runs_python_modules_outside_the_scanned_checkout() -> None:
    """``python -m`` imports from its working directory first, and the example scans untrusted code."""
    workflow = _load_yaml(ROOT / "examples" / "github-action-code-scan.yml")
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    modules = [step for step in steps if re.search(r"\bpython3? -m\b", step.get("run", ""))]
    assert modules, "the example should install and validate the scanner with python -m"
    for step in modules:
        assert step.get("working-directory") == "${{ runner.temp }}", (
            f"step {step.get('name')!r} runs `python -m` inside the scanned checkout"
        )


def test_secret_check_runs_on_the_same_files_in_the_hook_and_ci() -> None:
    """The script owns its exclusions, so the hook and CI cannot drift apart."""
    hooks = {
        hook["id"]: hook
        for repo in _load_yaml(ROOT / ".pre-commit-config.yaml")["repos"]
        for hook in repo.get("hooks", [])
    }
    hook = hooks["no-hardcoded-secrets"]
    assert hook["entry"] == "python tools/check_secrets.py"
    assert hook.get("types") == ["text"], "the hook must scan every text file"
    assert not {"exclude", "files", "types_or"} & hook.keys(), "exclusions belong in the script"
    steps = [
        step
        for job in _load_yaml(GITHUB / "workflows" / "ci.yml")["jobs"].values()
        for step in job.get("steps") or []
        if "tools/check_secrets.py" in str(step.get("run", ""))
    ]
    assert len(steps) == 1, "CI must run the secret check exactly once per test job"
    lines = [line.strip() for line in steps[0]["run"].splitlines()]
    assert lines[0] == "set -euo pipefail", "a failed `git ls-files` must fail the step"
    assert "git ls-files -z | xargs -0 python tools/check_secrets.py" in lines


def test_pre_commit_hooks_select_files_with_types_or() -> None:
    """`types` is an AND filter; a hook listing two types would never run."""
    config = _load_yaml(ROOT / ".pre-commit-config.yaml")
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            types = hook.get("types") or []
            assert len(types) <= 1, f"hook {hook['id']} lists {types} under `types`; use `types_or`"


#: A suppression and its reason. One line can break two rules at once -- a
#: broad `except ... : pass` in a teardown path is both BLE001 and S110 -- so
#: the codes are a list, and the reason follows all of them.
_SUPPRESSION = re.compile(r"#\s*noqa:\s*(?P<codes>[A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*)(?:\s*-\s*(?P<reason>.*))?$")
#: Rules whose suppression must say why. Both mark a deliberately swallowed
#: failure, which is exactly the kind a reader needs the reason for.
_REASONED_RULES = ("BLE001", "S110", "S112")


def test_suppressions_of_swallowed_failures_give_a_reason() -> None:
    """Every suppressed broad `except` or silent pass states why it is intentional."""
    bare = []
    for directory in ("shadowscan", "tools", "tests"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                match = _SUPPRESSION.search(line)
                if match is None:
                    continue
                codes = {code.strip() for code in match.group("codes").split(",")}
                if not codes & set(_REASONED_RULES):
                    continue
                if not (match.group("reason") or "").strip():
                    bare.append(f"{path.relative_to(ROOT)}:{number}")
    assert not bare, f"write `# noqa: <CODES> - <reason>`: {bare}"


def _package_bandit_suppressions() -> Iterator[tuple[str, str, set[str], str]]:
    """Each bandit (S) suppression in the shipped package: location, line, codes and reason."""
    for path in sorted((ROOT / "shadowscan").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = _SUPPRESSION.search(line)
            if match is None:
                continue
            codes = {code.strip() for code in match.group("codes").split(",")}
            if any(re.fullmatch(r"S\d+", code) for code in codes):
                yield f"{path.relative_to(ROOT)}:{number}", line, codes, (match.group("reason") or "").strip()


def test_package_bandit_suppressions_give_one_reason() -> None:
    """pyproject.toml says every S suppression in the package is a reviewed decision with a reason."""
    unreasoned = [
        where
        for where, line, _, reason in _package_bandit_suppressions()
        if not reason or line.count("# noqa") != 1
    ]
    assert not unreasoned, f"write one `# noqa: <CODES> - <reason>` per line: {unreasoned}"


#: A lint suppression comment: `noqa` for its line or, after `ruff:` or
#: `flake8:`, for its whole file. Matched ignoring case, as ruff reads the
#: line form.
_NOQA_DIRECTIVE = re.compile(r"#\s*(?:(?:ruff|flake8)\s*:\s*)?noqa", re.IGNORECASE)
_NOQA_CODES = re.compile(r"\s*:\s*[A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*")


def test_noqa_comments_name_the_rules_they_suppress() -> None:
    """A blanket `noqa` silences every rule, bandit's included, and names none.

    The tests above read only `# noqa: <CODES>`, so a blanket one got past
    them and still suppressed S602. Ruff's PGH004 rejects it in lint; this
    holds the paths ruff checks to it should the select list change.
    """
    excluded = [ROOT / entry for entry in _pyproject()["tool"]["ruff"]["exclude"]]
    blanket = []
    for directory in ("shadowscan", "tests", "tools", "benchmarks"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if "noqa" not in text.lower() or any(path.is_relative_to(entry) for entry in excluded):
                continue
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type != tokenize.COMMENT:
                    continue
                for directive in _NOQA_DIRECTIVE.finditer(token.string):
                    if not _NOQA_CODES.match(token.string, directive.end()):
                        blanket.append(f"{_relative(path)}:{token.start[0]}")
    assert not blanket, f"name the codes: `# noqa: <CODES> - <reason>`: {blanket}"


def test_partial_path_suppressions_name_the_program_they_start() -> None:
    """An S607 reason is about the executable on its own line, not one copied from another call."""
    misnamed = []
    for where, line, codes, reason in _package_bandit_suppressions():
        program = re.search(r'\[\s*"([^"]+)"', line)
        if "S607" in codes and (program is None or program.group(1) not in reason):
            misnamed.append(where)
    assert not misnamed, f"name the program each S607 suppression starts: {misnamed}"


def test_dev_extra_is_fully_pinned_for_ci() -> None:
    """Every development dependency must occur in a hash-locked CI input."""
    pinned = {
        name.lower().replace("_", "-")
        for text in (
            _read(ROOT / "requirements-ci.lock"),
            _read(ROOT / "requirements.lock"),
            _read(ROOT / "requirements-build.lock"),
        )
        for name in re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.MULTILINE)
    }
    for requirement in _pyproject()["project"]["optional-dependencies"]["dev"]:
        name = re.split(r"[<>=!\[; ]", requirement, maxsplit=1)[0].lower().replace("_", "-")
        assert name in pinned, f"[dev] requirement {requirement} has no exact pin in the constraints or lock"


def test_codeql_action_steps_share_one_release() -> None:
    """init, analyze and upload-sarif must run the same CodeQL Action release."""
    pins: dict[str, set[str]] = {}
    for workflow in WORKFLOWS:
        for match in re.finditer(
            r"github/codeql-action/([\w-]+)@([0-9a-f]{40})\s*#\s*(v\S+)", _read(workflow)
        ):
            pins.setdefault(match.group(2), set()).add(f"{workflow.name}:{match.group(1)} {match.group(3)}")
    assert pins, "no CodeQL Action steps found"
    assert len(pins) == 1, "CodeQL Action steps are pinned to different releases: " + "; ".join(
        f"{sha[:12]} -> {sorted(uses)}" for sha, uses in pins.items()
    )


# --- Documented counts match the code -----------------------------------------

# A claim about the shipped total: a signature count stated with its signal
# count ("215 signatures / 1001 signals", "178 signatures, 790 signals"), or
# one stated as the whole set ("all 212 signatures", "ships 215 signatures",
# "215 built-in signatures"). Other prose may count a subset ("two packs add
# 12 signatures") without claiming the total. Matching runs on text with its
# whitespace collapsed, so a claim wrapped across lines is still found.
_NUMBER = r"(\d[\d,]*)"
_PAIRED_SIGNATURE_CLAIM = re.compile(rf"\b{_NUMBER} signatures ?(?:/|,|and) ?{_NUMBER} signals\b")
_TOTAL_SIGNATURE_CLAIM = re.compile(
    rf"\b(?:all|ships|ship|bundles|includes) {_NUMBER} signatures\b"
    rf"|\b{_NUMBER} (?:bundled|built-in|shipped) signatures\b"
)
_CONNECTOR_CLAIM = re.compile(r"\*\*(\d+) connectors\*\*")


def _count(text: str) -> int:
    return int(text.replace(",", ""))


def _signature_claims(text: str) -> list[tuple[int, int | None]]:
    """``(signatures, signals or None)`` for every total-count claim in a document."""
    text = " ".join(text.split())
    claims: list[tuple[int, int | None]] = [
        (_count(match.group(1)), _count(match.group(2))) for match in _PAIRED_SIGNATURE_CLAIM.finditer(text)
    ]
    for match in _TOTAL_SIGNATURE_CLAIM.finditer(text):
        claims.append((_count(match.group(1) or match.group(2)), None))
    return claims


@pytest.mark.parametrize(
    "text,claims",
    [
        ("215 signatures / 1001 signals, YAML-defined", [(215, 1001)]),
        ("signature validation (178\n  signatures, 790 signals)", [(178, 790)]),
        ("216 signatures and 1,001 signals", [(216, 1001)]),
        ("shadowscan signatures list   # show all 212 signatures", [(212, None)]),
        ("ShadowScan ships 215\nsignatures / 1001 signals.", [(215, 1001), (215, None)]),
        ("the 215 built-in signatures", [(215, None)]),
        ("two packs add 12 signatures; 3 signatures share one prefix", []),
        ("the validator rejected 2 signatures", []),
    ],
)
def test_signature_count_claims_are_recognised(text: str, claims: list[tuple[int, int | None]]) -> None:
    assert _signature_claims(text) == claims


# Root documents that describe the current tree. The site includes SECURITY.md and GOVERNANCE.md as
# snippets, so a stale number there is published too. CHANGELOG.md and the engineering log
# (docs/engineering-log.md) are dated logs that quote earlier counts and are left out, as are the
# released sections of the release notes (docs/release-notes.md, formerly RELEASE_NOTES.md), which
# quote the counts of their own version (see ``_current_text``). benchmarks/ is left out for the same reason: its READMEs and run
# reports describe runs made at a recorded commit, so a total stated there belongs to that commit.
_CURRENT_ROOT_DOCS = ("README.md", "RELEASE_NOTES.md", "SECURITY.md", "GOVERNANCE.md", "CONTRIBUTING.md")
# The first heading of a released section in the release notes: ``## 0.1.1 — 2026-10-08``.
_RELEASED_HEADING = re.compile(r"^## \d+\.\d+", re.MULTILINE)
# The release notes (docs/release-notes.md) and the root RELEASE_NOTES.md that points to them.
_RELEASE_NOTES_NAMES = frozenset({"release-notes.md", "RELEASE_NOTES.md"})


# The dated engineering log quotes the counts of each entry's date, like CHANGELOG.md.
_DATED_DOCS = frozenset({"engineering-log.md"})


def _current_docs() -> list[Path]:
    """Documents that describe the current tree; dated review and engineering logs may quote old numbers.

    ``docs/history/`` holds relocated dated logs (the production candidate
    change history), which record numbers and defaults as they were at each
    change, so they are history for these checks too. Their links, whitespace
    and former-name hygiene are still checked by the walkers that enumerate
    documents themselves.
    """
    return [
        path
        for path in [*(ROOT / name for name in _CURRENT_ROOT_DOCS), *sorted((ROOT / "docs").rglob("*.md"))]
        if "hardening-logs" not in path.parts
        and path.name not in _DATED_DOCS
        and "history" not in path.parts
        and not re.search(r"review-\d{4}-\d{2}-\d{2}", path.name)
    ]


def _current_text(path: Path) -> str:
    """The part of a document that describes the current tree.

    The release notes keep one section per release below their ``## Unreleased`` section, and a
    released section states what that version shipped; only the text before the first released
    heading is checked. Every other document is checked whole.
    """
    text = _read(path)
    if path.name in _RELEASE_NOTES_NAMES:
        match = _RELEASED_HEADING.search(text)
        if match is not None:
            return text[: match.start()]
    return text


@pytest.mark.parametrize("name", sorted(_RELEASE_NOTES_NAMES))
def test_release_notes_are_checked_up_to_the_first_released_section(tmp_path: Path, name: str) -> None:
    current = "# Release notes\n\n## Unreleased\n\n- 10 signatures and 20 signals\n\n"
    released = "## 0.1.1 — 2026-10-08\n\n- 5 signatures and 9 signals\n\n## 0.1.0\n\n- 4 signatures\n"
    notes = tmp_path / name
    notes.write_text(current + released, encoding="utf-8")
    assert _current_text(notes) == current
    notes.write_text(current, encoding="utf-8")
    assert _current_text(notes) == current, "notes without a released section are checked whole"
    other = tmp_path / "README.md"
    other.write_text(current + released, encoding="utf-8")
    assert _current_text(other) == current + released, "only the release notes are sliced"


def test_the_release_notes_page_is_the_one_whose_released_sections_are_skipped() -> None:
    """The long-form release notes moved from RELEASE_NOTES.md to docs/release-notes.md."""
    notes = ROOT / "docs" / "release-notes.md"
    assert notes in _current_docs() and notes.name in _RELEASE_NOTES_NAMES
    assert _RELEASED_HEADING.search(_read(notes)), "docs/release-notes.md no longer has a released section"
    assert "docs/release-notes.md" in _read(ROOT / "RELEASE_NOTES.md"), "RELEASE_NOTES.md must point there"


def test_documented_signature_counts_match_the_shipped_packs(index) -> None:
    signatures = list(index.signatures.values())
    actual = (len(signatures), sum(len(signature.signals) for signature in signatures))
    claims = [(path, claim) for path in _current_docs() for claim in _signature_claims(_current_text(path))]
    assert any(path.name == "README.md" and signals is not None for path, (_, signals) in claims), (
        "README should state the signature and signal counts"
    )
    for path, (count, signals) in claims:
        assert count == actual[0] and signals in (None, actual[1]), (
            f"{_relative(path)} claims {count} signatures"
            + (f" / {signals} signals" if signals is not None else "")
            + f"; packs ship {actual[0]} / {actual[1]}. Describe a subset without "
            "'all', 'ships' or 'built-in' if it is not the shipped total."
        )


def test_documented_connector_counts_match_the_registry() -> None:
    actual = len(builtin_connector_names())
    claims = [
        (path, match) for path in _current_docs() for match in _CONNECTOR_CLAIM.finditer(_current_text(path))
    ]
    assert claims, "a doc should state the connector count in bold (**N connectors**)"
    for path, match in claims:
        assert int(match.group(1)) == actual, (
            f"{_relative(path)} claims {match.group(1)} connectors, registry has {actual}"
        )


# Connector configuration keys that may stay undocumented, each with a reason.
# Keep this empty unless a key is deliberately internal.
_UNDOCUMENTED_CONNECTOR_KEYS: dict[str, str] = {}


def test_every_connector_configuration_key_is_documented() -> None:
    """Every key `shadowscan connectors --json` lists is named in docs/connectors*.md."""
    docs = "\n".join(
        _read(path)
        for path in [ROOT / "docs" / "connectors.md", *sorted((ROOT / "docs" / "connectors").glob("*.md"))]
    )
    listed = set()
    missing = []
    for name in builtin_connector_names():
        connector = get_connector_class(name)
        for key in {**connector.config_keys, **connector.shared_config_keys}:
            listed.add(f"{name}.{key}")
            # Backticked as `key`, `key: value` or `key=value`.
            if f"{name}.{key}" not in _UNDOCUMENTED_CONNECTOR_KEYS and not re.search(
                rf"`{re.escape(key)}[`:= ]", docs
            ):
                missing.append(f"{name}.{key}")
    assert not missing, f"document these connector configuration keys in docs/connectors*.md: {missing}"
    assert _UNDOCUMENTED_CONNECTOR_KEYS.keys() <= listed, "stale undocumented-key exemptions"


def test_documented_realistic_corpus_file_range_matches_the_corpus() -> None:
    cases = json.loads(_read(ROOT / "tools" / "evaluation" / "realistic_corpus.json"))["cases"]
    counts = [len(case["files"]) for case in cases]
    match = re.search(
        r"snapshots \((\d+) to (\d+) files each\)", " ".join(_read(ROOT / "docs" / "evaluation.md").split())
    )
    assert match is not None, "docs/evaluation.md should state the realistic corpus file range"
    assert (int(match.group(1)), int(match.group(2))) == (min(counts), max(counts)), (
        f"docs/evaluation.md claims {match.group(0)!r}; the corpus has {min(counts)} to {max(counts)} files per case"
    )


def _gcp_pagination(index) -> dict[str, int]:
    """The page limits the GCP connector applies, measured by paging until it stops.

    Every response offers a fresh page token, so each paginated call runs to the
    connector's own cap. Nothing leaves the process: the transport is a stub.
    """
    connector = GcpConnector(ConnectorContext(config={"max_pages": 1_000_000}, index=index))
    connector.ctx.stats = ScanStats(connector="cloud.gcp", started_at="2026-01-01T00:00:00Z")
    tokens = itertools.count()
    connector._get = Mock(
        side_effect=lambda url, **params: {"items": [], "nextPageToken": f"t{next(tokens)}"}
    )
    list(connector._pages("https://compute.googleapis.com/compute/v1/projects", "items"))
    connector.http = Mock()
    connector.http.post_json.side_effect = lambda url, json: {
        "entries": [],
        "nextPageToken": f"t{next(tokens)}",
    }
    list(connector._collect_audit("demo"))
    default = GcpConnector(ConnectorContext(config={}, index=index)).max_pages
    return {
        "default": default,
        "lists": connector._get.call_count,
        "audit": connector.http.post_json.call_count,
    }


def test_documented_gcp_pagination_caps_match_the_connector(index) -> None:
    """Both GCP pages and the connector's own help state the caps it applies.

    Regression for a real fork: docs/connectors/cloud.md once dropped the caps
    sentence that docs/connectors.md still carried, understating GCP's
    collection limits on the page the site navigation links to.
    """
    pages = _gcp_pagination(index)
    caps = (
        f"resource lists stop at {pages['lists']} pages and "
        f"audit-log queries at {pages['audit']} pages regardless"
    )
    # Every connector caps max_pages at MAX_PAGES; the docs state both bounds.
    bounds = (
        f"default and maximum {MAX_PAGES}"
        if pages["default"] == MAX_PAGES
        else f"default {pages['default']}, maximum {MAX_PAGES}"
    )
    default = f"`max_pages` ({bounds})"
    for path in (ROOT / "docs" / "connectors.md", ROOT / "docs" / "connectors" / "cloud.md"):
        assert any(default in text and caps in text for text in _paragraphs(path)), (
            f"{_relative(path)} must say in one paragraph that {default} applies and that {caps}"
        )
    help_text = " ".join(GcpConnector.config_keys["max_pages"].split())
    assert f"capped at {MAX_PAGES}" in help_text and f"default {pages['default']}" in help_text
    assert caps in help_text


def test_endpoint_guide_names_every_google_ai_service_the_ebpf_host_rule_takes() -> None:
    """endpoint.ebpf's AI host rule takes the GCP connector's AI services; the guide lists
    them, so a service added there must be named in the guide too."""
    text = " ".join(_read(ROOT / "docs" / "connectors" / "endpoint.md").split())
    for host in GCP_AI_SERVICES:
        assert f"`{host.removesuffix('.googleapis.com')}`" in text, host
    assert "`aiplatform.mtls.googleapis.com`" in text


# --- Migration notes ------------------------------------------------------------


def _markdown_section(text: str, heading: str) -> str:
    """The body under one heading line, up to the next heading of the same or a higher level."""
    assert f"\n{heading}\n" in text, f"no {heading!r} heading"
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(f"\n{heading}\n") + len(heading) + 2
    end = re.compile(rf"^#{{1,{level}}} ", re.MULTILINE).search(text, start)
    return text[start : end.start() if end else len(text)]


def _connector_stats(connector: Any, records: list[dict[str, Any]]) -> tuple[list[Any], ScanStats]:
    connector.ctx.stats = ScanStats(connector=connector.name, started_at="2026-01-01T00:00:00Z")
    return list(connector.analyze(records)), connector.ctx.stats


def test_connector_migration_note_describes_the_connectors_as_they_behave() -> None:
    """Regression: the note said endpoint.host reports a row only when an AI product signature
    matches its name or path, which a bare osquery or MDM row for Ollama or LM Studio does not, and
    it left out two changes operators see against a baseline: resource attributes merged into
    nested gateway.otel spans, and native eBPF events with unread fields marking a scan incomplete.
    Each statement is checked against the connector before the note is required to make it."""
    heading = "## October 17 connector correctness migration (Unreleased)"
    note = " ".join(_markdown_section(_read(ROOT / "docs" / "production-migrations.md"), heading).split())

    # endpoint.host: a bare row naming a local runtime is reported, and so is every model store the
    # catalog lists below a home directory (the GPT4All and Jan stores among them, which a check
    # of ~/.ollama/models alone left unchecked); a directory merely named like one elsewhere is not.
    for row in ({"name": "Ollama"}, {"name": "LM Studio.app", "path": "/Applications/LM Studio.app"}):
        assert _connector_stats(HostConnector(ConnectorContext()), [row])[0], row
    stores = [{"path": f"~/{store.root}"} for store in MODEL_STORES]
    reported = [bool(_connector_stats(HostConnector(ConnectorContext()), [row])[0]) for row in stores]
    assert len(set(reported)) == 1, f"the catalog's model stores are not reported alike: {stores}, {reported}"
    elsewhere = {"path": "/srv/app/jan/models/user.rb"}
    assert not _connector_stats(HostConnector(ConnectorContext()), [elsewhere])[0]
    for phrase in (
        "names a known AI product or runtime, or an AI category",
        "known AI product or local model runtime",
        "Ollama",
        "LM Studio",
        "GPT4All",
        "`process`",
    ):
        assert phrase in note, f"the endpoint.host note should say {phrase!r}"
    store_claim = "below a home directory, a model store the endpoint catalog lists"
    assert (store_claim in note) is reported[0], "the endpoint.host note should say model stores are reported"
    assert ("model-store directory" in note) is not reported[0], (
        "the endpoint.host note should say whether a row naming only a model-store directory is reported"
    )
    assert "name or path matches an AI product signature or" not in note

    # gateway.otel: resource attributes merge into nested spans, giving new findings and providers.
    def nested(resource: dict[str, str], span: dict[str, str]) -> dict[str, Any]:
        def attributes(values: dict[str, str]) -> list[dict[str, Any]]:
            return [{"key": key, "value": {"stringValue": value}} for key, value in values.items()]

        spans = [{"name": "call", "attributes": attributes(span)}]
        return {
            "resourceSpans": [
                {"resource": {"attributes": attributes(resource)}, "scopeSpans": [{"spans": spans}]}
            ]
        }

    resource_only = nested({"service.name": "svc", "gen_ai.system": "anthropic"}, {})
    assert [finding.provider for finding in OtelConnector(ConnectorContext()).analyze([resource_only])] == [
        "anthropic"
    ]
    model_only = nested({"service.name": "svc", "gen_ai.system": "openai"}, {"gen_ai.request.model": "m"})
    assert [finding.provider for finding in OtelConnector(ConnectorContext()).analyze([model_only])] == [
        "openai"
    ]
    for phrase in ("resource attributes", "span attributes", "`unknown`", "new findings"):
        assert phrase in note, f"the gateway.otel note should say {phrase!r}"

    # endpoint.ebpf: a recognized event with a wrong-typed field marks the scan incomplete, and
    # the list limit, like malformed fields, is warned once per producer, not once per scan.
    tracee = {"eventName": "security_socket_connect", "processName": "uvicorn", "args": "remote_addr"}
    _, stats = _connector_stats(EbpfConnector(ConnectorContext()), [tracee, tracee])
    assert stats.incomplete
    assert len(stats.warnings) == 1
    long_tracee = {**tracee, "args": [{"name": "fd", "value": 3}] * 101}
    long_hubble = {
        "flow": {"destination_names": ["a.example"] * 101, "l4": {"TCP": {"destination_port": 443}}}
    }
    _, stats = _connector_stats(EbpfConnector(ConnectorContext()), [long_tracee, long_hubble, long_hubble])
    assert stats.incomplete
    assert len(stats.warnings) == 2 and all("list limit" in warning for warning in stats.warnings)
    for phrase in (
        "wrong type",
        "100 entries",
        "one warning per producer",
        "one per producer for the list limit",
    ):
        assert phrase in note, f"the endpoint.ebpf note should say {phrase!r}"


def test_connector_finding_churn_has_a_migration_note() -> None:
    """Regression: #256 changed three offline connectors' findings with no rebaseline guidance.

    Nested OTLP exports reached gateway.otel without their resource attributes, so callers merged
    into one ``unknown-service`` finding; each service is now its own finding under a new id.
    endpoint.host stopped reporting rows nothing ties to AI, and endpoint.ebpf now reads native
    exports and marks a scan with unrecognized records incomplete. A comparison with an older
    baseline shows findings as resolved or new that are neither, and finding-identity changes
    need a migration note (AGENTS.md).
    """
    # A nested span without a service.name still gets the resource every nested caller used to get.
    span = {"attributes": [{"key": "gen_ai.system", "value": {"stringValue": "openai"}}]}
    nested = {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": [span]}]}]}
    [former] = [finding.resource for finding in OtelConnector(ConnectorContext()).analyze([nested])]
    heading = "## October 17 connector correctness migration (Unreleased)"
    note = " ".join(_markdown_section(_read(ROOT / "docs" / "production-migrations.md"), heading).split())
    for named in (
        "`gateway.otel`",
        "`endpoint.host`",
        "`endpoint.ebpf`",
        f"`{former}`",
        "incomplete (exit 3)",
    ):
        assert named in note, f"the connector migration note should name {named}"
    assert "baseline" in note, "the connector migration note should say to rebuild comparison baselines"
    entry = _markdown_section(
        _read(ROOT / "docs" / "engineering-log.md"),
        "### Review fixes: connector correctness, CI check names, benchmark framing (October 17)",
    )
    assert "(production-migrations.md#october-17-connector-correctness-migration-unreleased)" in entry, (
        "the #256 engineering-log entry should link its migration note"
    )


# --- Documented report and transport behaviour matches the code --------------

# How the documents name each character after which the CSV reporter can put a
# formula marker inside a cell.
_CSV_SEPARATOR_NAMES = {
    ",": "`,`",
    ";": "`;`",
    "|": "`|`",
    "\t": "tab",
    "\n": "line break",
    "\r": "line break",
}
_READ_DEADLINE_CLAIM = re.compile(r"within (\w+) the client timeout \((\d+) seconds by default\)")
_READ_DEADLINE_FACTORS = {"twice": 2}
# The implemented security controls and their limits; SECURITY.md held them until it was cut down to the
# reporting policy and a threat model at a glance.
SECURITY_CONTROLS = ROOT / "docs" / "security" / "controls.md"


def _paragraphs(path: Path) -> list[str]:
    """Blank-line separated blocks of a document, each on one line."""
    return [" ".join(block.split()) for block in re.split(r"\n[ \t]*\n", _read(path))]


# The page that explains the CSV formula markers to report consumers; the README did until it was cut down.
CSV_MARKER_PAGE = ROOT / "docs" / "getting-started" / "quickstart.md"


def test_documented_csv_markers_match_the_reporter() -> None:
    # Consumers strip the markers the documents describe. A consumer told only
    # about a leading marker corrupts every value with a marker inside it.
    candidates = [chr(code) for code in range(1, 128)] + ["\x85", "\xa0", "\u2028", "\u2029"]
    # A control character is rendered visibly in the cell; only a "'" before
    # the formula marks it.
    inside = {sep for sep in candidates if _safe_cell(f"a{sep}=1") == f"a{sep}'=1"}
    assert inside, "the CSV reporter no longer marks a formula inside a cell; update this test"
    unnamed = inside - _CSV_SEPARATOR_NAMES.keys()
    assert not unnamed, f"name {sorted(unnamed)!r} here and in the CSV documentation"
    names = sorted({_CSV_SEPARATOR_NAMES[sep] for sep in inside})
    claims = [
        (path, paragraph)
        for path in _current_docs()
        for paragraph in _paragraphs(path)
        if "csv" in paragraph.lower() and "`'`" in paragraph
    ]
    assert any(path == CSV_MARKER_PAGE for path, _ in claims), (
        f"{_relative(CSV_MARKER_PAGE)} should describe the CSV markers"
    )
    for path, paragraph in claims:
        missing = [name for name in names if name not in paragraph]
        assert not missing, f"{_relative(path)} describes CSV markers without the separators {missing}"


def test_documented_http_read_deadline_matches_the_client() -> None:
    claims = [
        (path, match)
        for path in _current_docs()
        for paragraph in _paragraphs(path)
        for match in _READ_DEADLINE_CLAIM.finditer(paragraph)
    ]
    assert any(path == SECURITY_CONTROLS for path, _ in claims), (
        f"{_relative(SECURITY_CONTROLS)} should state the read deadline"
    )
    expected = (http.READ_DEADLINE_FACTOR, http.DEFAULT_TIMEOUT * http.READ_DEADLINE_FACTOR)
    for path, match in claims:
        claimed = (_READ_DEADLINE_FACTORS.get(match.group(1)), int(match.group(2)))
        assert claimed == expected, f"{_relative(path)} says {match.group(0)!r}; the client uses {expected}"


def test_documented_automatic_deadline_ceiling_matches_the_probe() -> None:
    """The engineering log states the most the filesystem probe can propose, not the engine's cap.

    Regression: the entry said the deadline scales "capped at 30 minutes", the
    engine's ceiling, which a probe that stopped counting at 20,000 entries never
    reached: the proposal saturated at 200 seconds. The probe now counts as far
    as the ceiling; the claim must still be the probe's own arithmetic.
    """
    probe = FilesystemConnector
    ceiling = DEFAULT_CONNECTOR_TIMEOUT * probe._PROBE_LIMIT / probe._ENTRIES_PER_DEFAULT_BUDGET
    claim = (
        f"counts up to {probe._PROBE_LIMIT:,} entries",
        f"at most {ceiling:.0f} seconds at the {DEFAULT_CONNECTOR_TIMEOUT:.0f}-second default",
    )
    log = ROOT / "docs" / "engineering-log.md"
    assert any(all(part in paragraph for part in claim) for paragraph in _paragraphs(log)), (
        f"{_relative(log)} must say that code.filesystem {claim[0]} and proposes {claim[1]}"
    )


# A connector deadline set to the default's value, as a configuration key (YAML or Python) or a
# command-line flag, on a line that is not a comment.
_EXPLICIT_DEFAULT_TIMEOUT = re.compile(
    r"^[^#\n]*?(?:\bconnector_timeout(?:_seconds)?\s*[:=]\s*|--connector-timeout(?:-seconds)?[ =]+)"
    rf"{DEFAULT_CONNECTOR_TIMEOUT:.0f}(?:\.0*)?(?![\w.])",
    re.MULTILINE,
)
_CODE_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})[^\n]*\n(.*?)^[ \t]*\1[ \t]*$", re.MULTILINE | re.DOTALL)
# Dated records quote what a page or a configuration once said; prose may name the setting it warns
# against. Only the configurations and commands people copy are checked.
_DATED_RECORDS = frozenset(
    {"CHANGELOG.md", "RELEASE_NOTES.md", "docs/release-notes.md", "docs/engineering-log.md"}
)


def _copyable_samples() -> Iterator[tuple[str, str]]:
    """Every code block of the live documentation, and every example file, with where it is."""
    for path in _markdown_files():
        dated = _relative(path) in _DATED_RECORDS or path.is_relative_to(ROOT / "docs" / "history")
        if dated or any(path.is_relative_to(ROOT / folder) for folder in ("archive", "benchmarks")):
            continue
        for match in _CODE_FENCE.finditer(_read(path)):
            yield _relative(path), match.group(2)
    for path in sorted((ROOT / "examples").rglob("*")):
        if path.is_file() and path.suffix != ".md":
            yield _relative(path), _read(path)


def test_explicit_default_timeout_check_flags_only_live_settings() -> None:
    flagged = (
        "  connector_timeout_seconds: 120      # cooperative deadline per connector\n",
        "options:\n  connector_timeout: 120.0\n",
        "shadowscan code . --connector-timeout-seconds 120\n",
        "ScanConfig(connector_timeout_seconds=120)\n",
    )
    passed = (
        "  # connector_timeout_seconds: 120    # omit it to let the deadline scale\n",
        "  connector_timeout_seconds: 1200\n",
        "  connector_timeout_seconds: 120.5\n",
        "shadowscan code . --connector-timeout-seconds 300\n",
    )
    assert all(_EXPLICIT_DEFAULT_TIMEOUT.search(text) for text in flagged)
    assert not any(_EXPLICIT_DEFAULT_TIMEOUT.search(text) for text in passed)
    fenced = "Prose `connector_timeout_seconds: 120` stays.\n\n```yaml\noptions:\n  parallel: 2\n```\n"
    assert [match.group(2) for match in _CODE_FENCE.finditer(fenced)] == ["options:\n  parallel: 2\n"]


def test_no_sample_configuration_sets_the_default_connector_timeout() -> None:
    """Regression: README's full reference, the getting-started page, the production guide and the
    plugin example set ``connector_timeout_seconds: 120``. Only the unset default is raised to fit
    a large tree; a value someone sets, 120 included, is honoured unchanged, so a configuration
    copied from those samples gave a large repository a fixed 120 seconds and an incomplete scan.
    A sample leaves the option out, or sets a value it means to fix."""
    explicit = [
        f"{where}: {match.group(0).strip()}"
        for where, text in _copyable_samples()
        for match in _EXPLICIT_DEFAULT_TIMEOUT.finditer(text)
    ]
    assert not explicit, f"samples fix the default connector deadline, which disables its scaling: {explicit}"


_PLUGIN_EXECUTION_ROW = re.compile(r"^\| `plugin_execution` \| `(\w+)` \|", re.MULTILINE)
_PLUGIN_EXECUTION_DEFAULT_CLAIM = re.compile(
    r"\bdefaults?\b[^.;`]{0,40}`(?:options\.)?(?:plugin_execution: )?(thread|process)`"
)


def test_documented_plugin_execution_default_matches_the_config() -> None:
    # A page that still names the former thread default tells operators that
    # plugins run in the scanner process, where they cannot be stopped.
    default = ScanConfig().plugin_execution
    assert ScanConfig.from_dict({"options": {}}).plugin_execution == default
    [row] = _PLUGIN_EXECUTION_ROW.findall(_read(ROOT / "docs" / "architecture.md"))
    assert row == default, f"docs/architecture.md lists {row!r}; the default is {default!r}"
    claims = [
        (path, match)
        for path in _current_docs()
        for paragraph in _paragraphs(path)
        for match in _PLUGIN_EXECUTION_DEFAULT_CLAIM.finditer(paragraph)
    ]
    assert {"production.md", "connectors.md"} <= {path.name for path, _ in claims}
    for path, match in claims:
        assert match.group(1) == default, (
            f"{_relative(path)} says {match.group(0)!r}; the default is {default!r}"
        )


_FIXTURE_CLAIM = re.compile(r"(\d+) of (\d+) connectors ship fixtures")


def test_documented_fixture_connector_count_matches_the_demo_configuration() -> None:
    demo = yaml.safe_load((ROOT / "examples" / "shadowscan.offline.yaml").read_text(encoding="utf-8"))
    configured = {entry["name"] for entry in demo["connectors"]}
    assert configured <= set(builtin_connector_names())
    actual = (len(configured), len(builtin_connector_names()))
    claims = [(path, match) for path in _current_docs() for match in _FIXTURE_CLAIM.finditer(_read(path))]
    assert claims, "the README should state how many connectors the offline demo covers"
    for path, match in claims:
        claimed = (int(match.group(1)), int(match.group(2)))
        assert claimed == actual, f"{_relative(path)} claims {claimed}, the demo configures {actual}"


_GAP_BUDGET_CLAIM = re.compile(r"(\d+(?:\.\d+)?)% coverage budget")


def test_documented_coverage_budget_matches_the_default() -> None:
    """The README states the gap budget; the code sets it.

    Every other count in this README is pinned to the code. The fail-closed
    wording describes behaviour an operator relies on for a CI gate, so it is
    pinned too rather than left to drift the way it did when the budget was
    introduced.
    """
    actual = DEFAULT_MAX_GAP_RATIO * 100
    claims = [(path, m) for path in _current_docs() for m in _GAP_BUDGET_CLAIM.finditer(_read(path))]
    assert claims, "the README should state the coverage-gap budget"
    for path, match in claims:
        claimed = float(match.group(1))
        assert claimed == actual, (
            f"{_relative(path)} claims a {claimed}% budget; DEFAULT_MAX_GAP_RATIO is {actual}%"
        )


def test_ci_never_deselects_the_slow_timed_sweeps() -> None:
    """``make test-fast`` is a local convenience; CI must still run everything.

    The slow marker covers the ReDoS sweeps, which are the tests most worth
    keeping and the most tempting to skip when a pipeline is over time.
    """
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = _read(workflow)
        assert "not slow" not in text, (
            f"{_relative(workflow)} deselects the slow tests; they are the ReDoS and "
            "linearity sweeps and CI is the one place that must run them"
        )


def test_the_fail_closed_summary_names_the_coverage_budget() -> None:
    """The one line an operator reads before wiring exit 3 into a CI gate.

    Deliberately checks two known claims rather than scanning prose for
    "limit" near "exit 3": that search matched a byte cap on a config read
    and a lineage tracing bound, neither of which has anything to do with
    coverage. A checker with false positives gets suppressed, and then it
    guards nothing -- the same failure this budget exists to prevent.
    """
    readme = _read(ROOT / "README.md")
    summary = next(
        (line for line in readme.splitlines() if line.startswith("| **Fail-closed design**")),
        None,
    )
    assert summary is not None, "the README should keep its fail-closed capability row"
    assert "budget" in summary.lower(), (
        "the fail-closed row must say that bounded gaps are budgeted, not that every "
        f"limit produces exit 3: {summary}"
    )
    assert "report" in summary.lower(), "it must also say a tolerated gap is still reported"

    pipeline = next((para for para in re.split(r"\n\s*\n", readme) if "fail closed:" in para), None)
    assert pipeline is not None, "the README should keep its fail-closed pipeline paragraph"
    assert "budget" in pipeline, "the pipeline paragraph must name the coverage budget"
    assert "strict_coverage" in pipeline, "and the option that restores strict accounting"


_LIVE_CLAIM = re.compile(r"(\d+) of the (\d+) connectors collect from a live API")


def test_documented_live_connector_count_matches_the_declared_capability() -> None:
    """The README says how many connectors reach a live API; the classes declare it.

    "Live and offline modes" alone let a reader assume every connector does
    both. Ten read an export something else produced and have no API to call,
    so the split is published -- and pinned here, because a disclosure that
    silently goes stale is worse than none.
    """
    names = builtin_connector_names()
    live = sum(1 for name in names if get_connector_class(name).live_collection)
    actual = (live, len(names))
    claims = [(path, match) for path in _current_docs() for match in _LIVE_CLAIM.finditer(_read(path))]
    assert claims, "the README should state how many connectors collect from a live API"
    for path, match in claims:
        claimed = (int(match.group(1)), int(match.group(2)))
        assert claimed == actual, f"{_relative(path)} claims {claimed}, the classes declare {actual}"


def test_every_offline_only_connector_actually_refuses_to_collect() -> None:
    """``live_collection = False`` must describe the code, not merely annotate it."""
    for name in builtin_connector_names():
        cls = get_connector_class(name)
        if cls.live_collection:
            continue
        source = inspect.getsource(cls.collect)
        assert "raise" in source, f"{name} declares no live collection but its collect() does not refuse"


_DEMO_COMMAND = "$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows "
_DEMO_TOTALS = re.compile(r"(\d+) findings  •  (\d+) shadow \(inventory: (\d+) registered agents\)")
_DEMO_LEVELS = re.compile(r"\b(critical|high|medium|low|info) (\d+)\b")
_DEMO_SURFACES = re.compile(r"\b(cloud|code|endpoint|gateway|identity|lowcode|network|runtime|saas) (\d+)\b")
_DEMO_ROW = re.compile(r"^ ([A-Z]+) +(\d+)  (\S+) +(\S+) +(\S+) +(.+?)\s*$", re.MULTILINE)


def test_readme_demo_output_matches_the_offline_demo(index) -> None:
    """The README's abridged example is the current result of the bundled offline demo."""
    readme = _read(ROOT / "README.md")
    start = readme.index(_DEMO_COMMAND)
    block = readme[start : readme.index("```", start)]
    max_rows = int(block[len(_DEMO_COMMAND) :].split(None, 1)[0])
    header, _, table = block.partition("╰")
    totals = _DEMO_TOTALS.search(header)
    assert totals, "the README demo output should state the totals line"
    result = Engine(ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml"), index).run()
    findings = result.findings
    assert tuple(map(int, totals.groups())) == (
        len(findings),
        sum(1 for f in findings if f.shadow),
        result.inventory_size,
    ), "README demo totals are stale; rerun the command it shows"
    levels = Counter(f.risk.level.value for f in findings)
    surfaces = Counter(f.surface.value for f in findings)
    # The header is abridged: every number it shows must be current, not every number must be shown.
    for name, count in _DEMO_LEVELS.findall(header):
        assert levels[name] == int(count), f"README demo shows {name} {count}; the demo has {levels[name]}"
    for name, count in _DEMO_SURFACES.findall(header):
        assert surfaces[name] == int(count), (
            f"README demo shows {name} {count}; the demo has {surfaces[name]}"
        )
    expected = [
        (
            f.risk.level.value.upper(),
            f.risk.score,
            "SHADOW" if f.shadow else f.registry_match,
            f.surface.value,
            f.kind.value,
            f.title,
        )
        for f in findings[:max_rows]
    ]
    shown = [(lvl, int(score), *rest) for lvl, score, *rest in _DEMO_ROW.findall(table)]
    assert shown == expected, "README demo rows are stale; rerun the command it shows"


def _abridged(excerpt: Any, actual: Any) -> bool:
    """Whether ``excerpt`` abridges ``actual``: lists keep a subset, text ending in "…" a prefix."""
    if isinstance(excerpt, dict):
        return isinstance(actual, dict) and all(
            key in actual and _abridged(value, actual[key]) for key, value in excerpt.items()
        )
    if isinstance(excerpt, list):
        return isinstance(actual, list) and all(
            any(_abridged(item, candidate) for candidate in actual) for item in excerpt
        )
    if isinstance(excerpt, str) and excerpt.endswith("…"):
        return isinstance(actual, str) and actual.startswith(excerpt[:-1])
    return type(excerpt) is type(actual) and excerpt == actual


def test_abridged_excerpt_check_rejects_values_the_output_lacks() -> None:
    actual = {"a": [1, 2, 3], "text": "one two three", "n": 1}
    assert _abridged({"a": [3, 1], "text": "one two…"}, actual)
    assert not _abridged({"a": [4]}, actual)
    assert not _abridged({"text": "two…"}, actual)
    assert not _abridged({"n": True}, actual)
    assert not _abridged({"missing": 1}, actual)


def test_ci_guide_sarif_excerpt_is_the_first_result_of_the_offline_demo(index) -> None:
    """The CI guide's abridged SARIF result (the README's until it was cut down) is current demo output."""
    from shadowscan.reporters.sarif import render_sarif

    guide = _read(ROOT / "docs" / "operations" / "ci.md")
    start = guide.index("The same scan as SARIF")
    fence = guide.index("```json\n", start) + len("```json\n")
    excerpt = json.loads(guide[fence : guide.index("```", fence)])
    result = Engine(ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml"), index).run()
    first = json.loads(render_sarif(result))["runs"][0]["results"][0]
    assert _abridged(excerpt, first), (
        "docs/operations/ci.md SARIF excerpt is stale; rerun the demo with --format sarif"
    )


def test_detection_matrix_is_current() -> None:
    """The detection matrix page is generated from the signature packs and connector classes."""
    from tools.readme_matrix import PAGE, render, replace_block

    text = PAGE.read_text(encoding="utf-8")
    assert replace_block(text, render()) == text, f"{_relative(PAGE)} is stale; run `make readme-matrix`"


def test_readme_links_the_detection_matrix_page() -> None:
    """The matrix left the README for the docs site; the landing page must still lead to it."""
    from tools.readme_matrix import PAGE

    readme = _read(ROOT / "README.md")
    assert f"https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/{_relative(PAGE)}" in readme


_BENCHMARKS = ROOT / "benchmarks"


def _percentages(level: dict[str, Any]) -> str:
    return " / ".join(f"{level[key]:.1%}" for key in ("precision", "recall", "f1"))


# The page holding the benchmark results table and its caveats; the README's Benchmarks section did until
# the README was cut down to a landing page, which now only summarizes the caveat and links here.
BENCHMARK_PAGE = ROOT / "docs" / "evaluation.md"
BENCHMARK_HEADING = "## Benchmark results"


def _level2_section(text: str, heading: str) -> str:
    """The text from ``heading`` up to the next level-2 heading, wherever the section sits."""
    start = text.index(f"\n{heading}\n")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def _benchmark_section() -> str:
    return _level2_section(_read(BENCHMARK_PAGE), BENCHMARK_HEADING)


def test_benchmark_table_quotes_the_committed_results() -> None:
    """Every number in the published benchmark table comes from the committed metrics files."""
    section = _benchmark_section()
    estate_run = "shadowbench/estate/results/2026-10-11"
    estate_metrics = json.loads((_BENCHMARKS / estate_run / "metrics.json").read_text(encoding="utf-8"))
    corpus, tool = estate_metrics["corpus"], estate_metrics["tools"]["shadowscan"]
    entity = tool["entity_level"]
    negatives = corpus["control"] + corpus["nearmiss"]
    assert entity["fp"] + entity["tn"] == negatives
    estate = [
        f"blob/main/benchmarks/{estate_run}/REPORT.md",
        f"(2026-10-11, {tool['version']})",
        f"{corpus['entities']} authored vendor-format entities",
        f"{corpus['positive']} positive, {corpus['control']} control, {corpus['nearmiss']} near-miss",
        f"Entity precision / recall / F1 {_percentages(entity)}",
        f"{entity['positives_detected']} of {entity['positives']} positives found",
        f"{entity['fp']} of {negatives} controls and near-misses flagged",
    ]
    code_run = "shadow-ai-discovery/results/2026-10-09"
    code_metrics = json.loads((_BENCHMARKS / code_run / "metrics.json").read_text(encoding="utf-8"))
    corpus, tool = code_metrics["corpus"], code_metrics["tools"]["shadowscan"]
    repos = tool["repo_level"]
    # An incomplete run left content unread, so its clean control or near-miss
    # is not a clean result and the README has to say how many there were.
    labels = {
        entry["id"]: entry["class"]
        for entry in json.loads(
            (_BENCHMARKS / "shadow-ai-discovery" / "corpus.json").read_text(encoding="utf-8")
        )["repos"]
    }
    incomplete_negatives = sum(
        labels[repo] in {"control", "nearmiss"} for repo in tool["incomplete_runs"]["repos"]
    )
    assert incomplete_negatives
    code = [
        f"blob/main/benchmarks/{code_run}/REPORT.md",
        f"(2026-10-09, {tool['version']})",
        f"{corpus['repos']} public repositories pinned by SHA",
        f"{corpus['positive']} positive, {corpus['control']} control, {corpus['nearmiss']} near-miss",
        f"{corpus['expected_facts']} expected facts",
        f"Fact precision / recall / F1 {_percentages(tool['value_level']['in_scope'])}",
        f"{repos['positives_detected']} of {repos['positives']} positive repositories flagged",
        f"{repos['controls_flagged'] + repos['nearmiss_flagged']} of "
        f"{repos['controls'] + repos['nearmiss']} controls and near-misses flagged "
        f"({incomplete_negatives} of those {repos['controls'] + repos['nearmiss']} runs incomplete)",
        f"{tool['incomplete_runs']['count']} of {corpus['repos']} runs were incomplete (exit 3)",
        "an incomplete clean run is not a clean result",
    ]
    missing = [claim for claim in estate + code if claim not in section]
    assert not missing, "benchmark table no longer matches the committed metrics: " + repr(missing)
    assert "not** independent review" in section and "not** measured production precision" in section
    # The README no longer carries the table, but it must keep the authorship caveat and lead to it.
    readme = " ".join(_level2_section(_read(ROOT / "README.md"), "## Benchmarks").split())
    assert "not** independent review" in readme and "not** measured production precision" in readme
    assert "blob/main/docs/evaluation.md#benchmark-results" in readme


def test_benchmark_estate_row_says_when_the_labels_were_frozen() -> None:
    """The estate's labels were frozen after every runnable tool ran once, not before any tool ran.

    The README's benchmark table (now on the evaluation page) said the labels were "frozen before
    any tool ran", but the estate protocol froze them after a label-completeness audit in which
    every runnable tool ran once (the run report already says so).
    """
    section = " ".join(_benchmark_section().split())
    assert "frozen before any tool ran" not in section
    assert "label-completeness pass in which every runnable tool ran once" in section


def test_estate_benchmark_documents_say_later_shadowscan_runs_are_in_sample() -> None:
    """ShadowScan was tuned with the 2026-10-11 estate run's errors in view.

    Rule changes made after that run fix seven of its twelve ShadowScan errors on a replay, so a
    later ShadowScan run on the estate is in-sample. Every document that presents that run, and
    the changelog entry for those rules, has to say so, and the benchmark-derived note-taker
    recognition is marked as such.
    """
    documents = {
        _relative(BENCHMARK_PAGE): _benchmark_section(),
        "README.md": _level2_section(_read(ROOT / "README.md"), "## Benchmarks"),
        "benchmarks/shadowbench/README.md": _read(ROOT / "benchmarks/shadowbench/README.md"),
        "benchmarks/shadowbench/estate/README.md": _read(ROOT / "benchmarks/shadowbench/estate/README.md"),
    }
    unstated = [name for name, text in documents.items() if "in-sample" not in " ".join(text.split())]
    assert not unstated, f"no in-sample disclosure for later ShadowScan estate runs in {unstated}"
    # The estate row's "in-sample (below)" points at this explanation; the word alone in the
    # table cell must not stand in for it.
    benchmarks = " ".join(documents[_relative(BENCHMARK_PAGE)].split())
    for statement in (
        "detection rules were changed with that run's errors in view",
        "fewer errors on it are not evidence of better field accuracy",
    ):
        assert statement in benchmarks, (
            f"{_relative(BENCHMARK_PAGE)} benchmark results no longer say: {statement!r}"
        )
    changelog = _read(ROOT / "CHANGELOG.md")
    start = changelog.index("\n## [Unreleased]\n")
    unreleased = " ".join(changelog[start : changelog.index("\n## ", start + 1)].split())
    assert "in-sample" in unreleased
    assert re.search(r"Wudpecker and Tactiq[^.]*\(benchmark-derived", unreleased)


_PIP_COMMANDS = frozenset(
    {
        "cache", "check", "completion", "config", "debug", "download", "freeze", "hash", "help",
        "index", "inspect", "install", "list", "lock", "search", "show", "uninstall", "wheel",
    }
)  # fmt: skip
_COMMAND_SEPARATORS = frozenset({"&&", "||", "|", ";"})
_COMMAND_START = _COMMAND_SEPARATORS | {"then", "do", "time", "exec"}


def _invocations(words: list[str], tool: str) -> Iterator[list[str]]:
    """The arguments of each command ``tool`` starts in one shell line, up to the next command."""
    for position, word in enumerate(words):
        if (word == tool or word.endswith("/" + tool)) and (
            position == 0
            or words[position - 1] in _COMMAND_START
            or "=" in words[position - 1]
            or (tool == "pip" and words[position - 1] == "-m")
        ):
            rest = itertools.takewhile(lambda arg: arg not in _COMMAND_SEPARATORS, words[position + 1 :])
            yield [arg for arg in rest if not arg.startswith("-")]


def test_documented_command_arguments_stop_at_the_next_command() -> None:
    line = (
        "shadowscan --help && python -m shadowscan.signatures.validate"
        " && python -m shadowscan.mappings.validate"
    )
    assert list(_invocations(line.split(), "shadowscan")) == [[]]
    line = "python -m pip wheel . && shadowscan code . | tee out"
    assert list(_invocations(line.split(), "pip")) == [["wheel", "."]]
    assert list(_invocations(line.split(), "shadowscan")) == [["code", "."]]


def test_documented_commands_name_real_subcommands() -> None:
    """A command copied from a shell block reaches a real ShadowScan or pip subcommand.

    A lost space (``shadowscan code.`` or ``pip wheel.``) still reads as a
    command but fails for everyone who copies it.
    """
    import click

    from shadowscan.cli import main

    groups = {
        name: set(command.commands) if isinstance(command, click.Group) else None
        for name, command in main.commands.items()
    }
    problems = []
    for path in _markdown_files():
        for number, line in _shell_lines(_read(path)):
            words = [word.strip("\"'") for word in line.split()]
            for args in _invocations(words, "shadowscan"):
                if not args:
                    continue
                subcommands = groups.get(args[0], set())
                if args[0] not in groups or (
                    subcommands and len(args) > 1 and args[1][:1].isalpha() and args[1] not in subcommands
                ):
                    problems.append(f"{_relative(path)}:{number}: {line}")
            for args in _invocations(words, "pip"):
                if args and args[0] not in _PIP_COMMANDS:
                    problems.append(f"{_relative(path)}:{number}: {line}")
    assert not problems, "documented commands with no such subcommand:\n" + "\n".join(problems)


# `python -m MODULE`, also through a path, a versioned interpreter or interpreter
# options: flags (`-I`, `-OO`, `-Xdev`) and `-W`/`-X` with a separate argument
# (`-X dev`). A name a table elides (`python -m vllm.entrypoints…`) is checked
# up to the ellipsis.
_PYTHON_OPTION = r"(?:-[WX]\s+[^\s-]\S*|-[^\s\-cm]\S*)"
_PYTHON_MODULE = re.compile(rf"\bpython(?:3(?:\.\d+)?)?(?:\s+{_PYTHON_OPTION})*\s+-m\s+([^\s`'\";&|()<>]+)")
_FIRST_PARTY = frozenset({"benchmarks", "shadowscan", "tools"})


def _code(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, code)`` for each fenced-block line and each inline code span."""
    prose = dict(_prose_lines(text))
    for number, line in enumerate(text.splitlines(), start=1):
        if number not in prose:
            yield number, line
            continue
        for span in _INLINE_CODE.finditer(line):
            yield number, span.group()[1:-1]


def _python_modules(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, module)`` for each ``python -m`` command a document shows."""
    for number, code in _code(text):
        for match in _PYTHON_MODULE.finditer(code):
            yield number, match.group(1).removesuffix("…")


def _runnable(module: str) -> bool:
    """Whether ``python -m module`` finds code to run in this checkout."""
    try:
        spec = importlib.util.find_spec(module)
        if spec is not None and spec.submodule_search_locations is not None:
            spec = importlib.util.find_spec(f"{module}.__main__")  # a package runs its __main__
    except ModuleNotFoundError:  # a parent package is missing or is a plain module
        return False
    return spec is not None


def _module_problem(module: str) -> str | None:
    if not all(part.isidentifier() for part in module.split(".")):
        return "is not a module name"
    if module.partition(".")[0] in _FIRST_PARTY and not _runnable(module):
        return "is not a runnable module in this checkout"
    return None


def test_documented_python_modules_are_read_from_code_only() -> None:
    text = textwrap.dedent("""\
        The example runs `python -m` outside the checkout; python -m in prose is not a command.
        Run `python -m tools.connector_reference`, `.venv/bin/python3 -m pip check`
        or `python -m vllm.entrypoints…`.

        ```bash
        python -m shadowscan. signatures.validate && python -m tools.no_such_tool
        python -I -m shadowscan.signatures.validate && python3 -X dev -m pip check
        python3.12 -OO -Werror -m shadowscan.signatures.validat
        python -m benchmarks.sab_realworld && python -m benchmarks.sab_realworl
        python -u script.py -m not_a_module
        ```
        """)
    modules = list(_python_modules(text))
    assert modules == [
        (2, "tools.connector_reference"),
        (2, "pip"),
        (3, "vllm.entrypoints"),
        (6, "shadowscan."),
        (6, "tools.no_such_tool"),
        (7, "shadowscan.signatures.validate"),
        (7, "pip"),
        (8, "shadowscan.signatures.validat"),
        (9, "benchmarks.sab_realworld"),
        (9, "benchmarks.sab_realworl"),
    ]
    assert [module for _, module in modules if _module_problem(module)] == [
        "shadowscan.",
        "tools.no_such_tool",
        "shadowscan.signatures.validat",
        "benchmarks.sab_realworl",
    ]


def test_documented_python_modules_exist() -> None:
    """Every ``python -m`` command a document shows names a module, and a first-party one runs.

    A stray space (``python -m shadowscan. signatures.validate``) still reads as
    a command but fails for everyone who copies it. Third-party modules are only
    checked for a well-formed name.
    """
    problems = [
        f"{_relative(path)}:{number}: {module} {problem}"
        for path in _markdown_files()
        for number, module in _python_modules(_read(path))
        if (problem := _module_problem(module)) is not None
    ]
    assert not problems, "documented `python -m` commands that cannot run:\n" + "\n".join(problems)


def test_readme_quotes_a_declared_classifier() -> None:
    quoted = re.findall(r"package classifier is `([^`]+)`", _read(ROOT / "README.md"))
    assert quoted, "README should name the package classifier"
    assert set(quoted) <= set(_pyproject()["project"]["classifiers"]), quoted


def test_connector_configuration_reference_is_current() -> None:
    """docs/connectors/reference.md is generated from every built-in connector's keys."""
    from tools.connector_reference import REFERENCE, render

    assert REFERENCE.read_text(encoding="utf-8") == render(), (
        "docs/connectors/reference.md is stale; run `make connector-reference`"
    )


def test_mapping_catalog_reference_is_current() -> None:
    """docs/concepts/mappings-reference.md is generated from the packaged mapping catalogs and rules."""
    from tools.mapping_reference import REFERENCE, render

    assert REFERENCE.read_text(encoding="utf-8") == render(), (
        "docs/concepts/mappings-reference.md is stale; run `make mapping-reference`"
    )


def test_docs_name_the_registry_operation_the_aws_connector_calls() -> None:
    # registry_arns calls BatchGetDiscoverableRegistryRecord; a guide that names the
    # unbatched action tells operators to grant a permission that is never used.
    source = (ROOT / "shadowscan/connectors/cloud/aws.py").read_text(encoding="utf-8")
    assert "batch_get_discoverable_registry_record" in source
    stale = [
        path.relative_to(ROOT).as_posix()
        for path in _markdown_files()
        if re.search(r"(?<!Batch)GetDiscoverableRegistryRecord", path.read_text(encoding="utf-8"))
    ]
    assert not stale, stale


def test_make_install_rejects_the_interpreters_pyproject_rejects() -> None:
    """`make install` fails before the locked installs on a Python that `pip install -e .` would refuse."""
    makefile = _read(ROOT / "Makefile")
    bounds = re.search(r"\(3, (\d+)\) <= sys\.version_info\[:2\] < \(3, (\d+)\)", makefile)
    assert bounds is not None, "make ensure-python no longer checks the interpreter"
    requires = _pyproject()["project"]["requires-python"]
    assert requires == f">=3.{bounds.group(1)},<3.{bounds.group(2)}", (
        f"ensure-python allows 3.{bounds.group(1)} to below 3.{bounds.group(2)}; pyproject says {requires}"
    )
    assert re.search(r"^install install-dev: ensure-python$", makefile, re.M)


def _pre_commit_hook(hook_id: str) -> dict[str, Any]:
    for repo in _load_yaml(ROOT / ".pre-commit-config.yaml")["repos"]:
        for hook in repo["hooks"]:
            if hook["id"] == hook_id:
                return dict(hook)
    raise AssertionError(f"no {hook_id} hook in .pre-commit-config.yaml")


def _strip_trailing_whitespace(line: bytes, markdown: bool) -> bytes:
    """What pre-commit's trailing-whitespace hook (`--markdown-linebreak-ext=md`) writes for one line."""
    body = line.rstrip(b"\r\n")
    eol = line[len(body) :]
    if markdown and not body.isspace() and body.endswith(b"  "):
        return body[:-2].rstrip() + b"  " + eol
    return body.rstrip() + eol


def test_tracked_text_files_already_pass_the_whitespace_hooks() -> None:
    """`pre-commit run --all-files` on a clean checkout must not rewrite anything; CI runs no hooks."""
    end_of_file = re.compile(_pre_commit_hook("end-of-file-fixer").get("exclude", "(?!)"))
    whitespace = re.compile(_pre_commit_hook("trailing-whitespace").get("exclude", "(?!)"))
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    problems = []
    for name in filter(None, listed.decode().split("\0")):
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:  # binary, which the hooks skip
            continue
        if (
            data
            and not end_of_file.search(name)
            and (not data.endswith(b"\n") or not data.rstrip(b"\r\n") or data.endswith((b"\n\n", b"\n\r\n")))
        ):
            problems.append(f"{name}: must end with exactly one newline")
        if not whitespace.search(name):
            markdown = name.endswith(".md")
            if any(
                _strip_trailing_whitespace(line, markdown) != line for line in data.splitlines(keepends=True)
            ):
                problems.append(f"{name}: trailing whitespace")
    assert not problems, "fix these or add them to the hook's exclude:\n  " + "\n  ".join(problems)


def test_mypy_hook_excludes_what_pyproject_excludes() -> None:
    """pre-commit passes file names explicitly, which mypy's own `exclude` setting does not filter."""
    hook = _pre_commit_hook("mypy")
    scope = re.compile(hook["files"])
    exclude = re.compile(hook.get("exclude", "(?!)"))
    missed = [
        path
        for path in _pyproject()["tool"]["mypy"]["exclude"]
        if scope.search(path) and not exclude.search(path)
    ]
    assert not missed, f"add {missed} to the mypy hook's exclude in .pre-commit-config.yaml"


def test_workflow_readme_lists_every_workflow() -> None:
    readme = _read(GITHUB / "workflows" / "README.md")
    linked = set(re.findall(r"\]\(([\w.-]+\.ya?ml)\)", readme))
    assert linked == {path.name for path in WORKFLOWS}, (
        f"update .github/workflows/README.md: missing {sorted({p.name for p in WORKFLOWS} - linked)}, "
        f"stale {sorted(linked - {p.name for p in WORKFLOWS})}"
    )


def test_assurance_results_synthetic_case_count_matches_corpus() -> None:
    """docs/assurance-results.md's synthetic-corpus count tracks tools/evaluation/corpus.json.

    The prose states a current total ("has since grown to N authored synthetic
    cases (P positives, Q negatives)"). That is a live count of the committed
    corpus, so it earns the same documented-count guard the signature and
    connector totals get; a synthetic case is a positive when it sets
    ``present: true``. Whitespace is collapsed so a claim wrapped across lines is
    still found.
    """
    text = " ".join(_read(ROOT / "docs" / "assurance-results.md").split())
    match = re.search(r"(\d+) authored synthetic cases \((\d+) positives, (\d+) negatives\)", text)
    assert match, "docs/assurance-results.md no longer states the synthetic corpus case count"
    stated = tuple(int(match.group(index)) for index in (1, 2, 3))
    cases = json.loads(_read(ROOT / "tools" / "evaluation" / "corpus.json"))["cases"]
    present = sum(1 for case in cases if case.get("present") is True)
    absent = sum(1 for case in cases if case.get("present") is False)
    assert present + absent == len(cases), "every evaluation case must set present true or false"
    assert stated == (len(cases), present, absent), (
        f"docs/assurance-results.md says {stated[0]} cases ({stated[1]} positives, {stated[2]} "
        f"negatives) but tools/evaluation/corpus.json has {len(cases)} ({present} positives, "
        f"{absent} negatives)"
    )


@pytest.mark.parametrize(
    "name", ["SECURITY.md", "docs/security/controls.md", "docs/production.md", "docs/connectors.md"]
)
def test_plugin_isolation_docs_name_the_parent_environment_route(name: str) -> None:
    """Regression: the guides said a process-mode worker is started without the credentials, but
    not that a plugin running as the scanner's user still reads every one of them from its
    parent's ``/proc/<ppid>/environ``, nor what keeps a credential from an untrusted plugin."""
    text = " ".join(_read(ROOT / name).split())
    assert "/proc/<ppid>/environ" in text, f"{name} must name the parent's /proc/<ppid>/environ"
    assert "lifecycle isolation, not a" in text, f"{name} must say process mode is not a sandbox"
    assert "secrets manager" in text, f"{name} must recommend files or a secrets manager"
    assert "under a separate user or in a separate container" in text, (
        f"{name} must recommend a separate user or container for an untrusted plugin"
    )


# Statements the unified coverage semantics made false: strict accounting has two
# spellings, the budget is judged per root and repository, and gaps the scanner can
# bound are budgeted rather than fatal on their own. Matched case-insensitively on
# whitespace-normalized text.
_STALE_COVERAGE_CLAIMS = (
    "restore the previous behaviour exactly",
    "restores the previous accounting exactly",
    "every other link makes the scan incomplete",
    "charged to one coverage budget for the run",
    "fails closed on every gap",
    "dangling test certificate links each exit 3 by default",
    "it conflicts with `strict_coverage`",
    # The ci profile's other gaps are judged by the budget, not exit 3 on their own.
    "every other gap still exits 3",
    "every other gap still marks the scan incomplete",
    # An incidental oversize file is one budgeted entry.
    "still exits 3 under the default settings",
    "any other oversize analyzable file makes coverage incomplete",
    # Binary fixtures cost a whole entry each: about 2% of a root exhaust it.
    "seeded with hundreds",
    # A file left unread for credentials is never declared.
    "unread for credentials; declared omission",
    # A malformed fixture records one to three quarter-weight gaps, not one.
    "a malformed fixture costs a quarter of an entry",
    "up to about 8% of its entries (2% at a quarter each)",
    "a root tolerates malformed fixtures up to about 8% of its entries and",
    # Manifests and shared client names are not agent configuration.
    "expect exit 3 for a monorepo that links",
)


def test_coverage_docs_state_the_unified_semantics() -> None:
    sources = [
        *_current_docs(),
        ROOT / "shadowscan" / "connectors" / "code" / "filesystem.py",
        ROOT / "shadowscan" / "cli" / "_scan.py",
    ]
    for path in sources:
        text = (
            " ".join(_current_text(path).split()).lower()
            if path.suffix == ".md"
            else " ".join(_read(path).split()).lower()
        )
        for claim in _STALE_COVERAGE_CLAIMS:
            assert claim not in text, f"{_relative(path)} still says {claim!r}"
    scanning = " ".join(_read(ROOT / "docs" / "scanning.md").split())
    assert "### Coverage budget and strict accounting" in _read(ROOT / "docs" / "scanning.md")
    for statement in (
        "are both strict accounting",
        "The budget is judged per scan root, and per repository for `code.github` and `code.gitlab`",
        "the `allowance` is the sum of their allowances",
        "`summary.tolerated_gaps`",
    ):
        assert statement in scanning, f"docs/scanning.md no longer says {statement!r}"
    keys = FilesystemConnector.config_keys
    assert "strict accounting" in keys["max_coverage_gap"] and "strict accounting" in keys["strict_coverage"]
