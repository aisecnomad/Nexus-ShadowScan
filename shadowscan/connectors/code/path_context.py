"""Path-derived evidence context for the filesystem connector.

Tests, documentation, examples, generated files and CI pipelines are
recognized from a file's path alone. Evidence there is kept but discounted
(``NegativeContext``), so it cannot inflate a finding into a deployed agent;
see the ``shadowscan.connectors.code.filesystem`` module docstring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from shadowscan.connectors.code.catalogs import _PIPELINE_DIRECTORIES, _PIPELINE_NAMES

# Paths whose evidence describes examples, documentation or generated output
# rather than a deployed agent. Like tests, evidence in these paths is kept
# but discounted so it does not inflate the finding.
DOCS_WEIGHT_SCALE = 0.5
DOCS_MAX_CONFIDENCE = 0.85
EXAMPLE_PATH_WEIGHT_SCALE = 0.5
EXAMPLE_PATH_MAX_CONFIDENCE = 0.85
GENERATED_WEIGHT_SCALE = 0.4
GENERATED_MAX_CONFIDENCE = 0.7


# Test suites routinely construct agents to exercise a library. Evidence found
# only there describes the library's tests, not a deployed agent, so it cannot
# establish an agent on its own unless ``include_tests`` is set.
_TEST_DIR_NAMES = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "testing",
        "fixtures",
        "__fixtures__",
        "__mocks__",
        "cassettes",
        "testdata",
        "test_data",
        "test-data",
        "e2e",
    }
)
_TEST_FILE_RE = re.compile(
    r"(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|conftest\.py|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?"
    r"|tests\.rs|[^/]*_tests?\.rs)$",
    re.IGNORECASE,
)


def _is_pipeline_file(rel: str) -> bool:
    """Whether ``rel`` is a CI pipeline, whose ``image:`` lines name job containers, not deployments."""
    path = PurePosixPath(rel)
    parts = path.parts
    name = path.name
    return (
        (".github" in parts and "workflows" in parts)
        or name in _PIPELINE_NAMES
        or name == "Jenkinsfile"
        or name.startswith(".woodpecker")
        or not _PIPELINE_DIRECTORIES.isdisjoint(parts[:-1])
    )


def _is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    return any(part in _TEST_DIR_NAMES for part in parts[:-1]) or bool(_TEST_FILE_RE.search(rel))


_DOCS_DIR_NAMES = frozenset({"docs", "doc", "documentation", "wiki", "guides", "tutorials"})

_EXAMPLE_DIR_NAMES = frozenset(
    {
        "examples",
        "example",
        "samples",
        "sample",
        "demos",
        "demo",
        "quickstart",
        "quickstarts",
        "tutorial",
        "tutorials",
        "starter",
        "starters",
        "templates",
        "boilerplate",
        "cookbooks",
        "cookbook",
        "recipes",
    }
)

# Generated code is recognized by the file name a generator gives it, never by a
# directory name: "codegen" or "generated" also names a service that runs an
# LLM code-generation agent. "*.auto.*" is not a marker either (Terraform loads
# "*.auto.tfvars" into the deployment).
_GENERATED_FILE_RE = re.compile(
    r"(?:^|/)(?:[^/]*\.generated\.[^/]+|[^/]*_pb2\.py|[^/]*_pb2_grpc\.py)$",
    re.IGNORECASE,
)


def _is_docs_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    return any(part in _DOCS_DIR_NAMES for part in parts[:-1])


def _is_example_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    return any(part in _EXAMPLE_DIR_NAMES for part in parts[:-1])


def _is_generated_path(rel: str) -> bool:
    return bool(_GENERATED_FILE_RE.search(rel.lower()))


@dataclass(frozen=True, slots=True)
class NegativeContext:
    """A recognized context that discounts evidence without discarding it."""

    reason: str
    weight_scale: float
    confidence_cap: float | None = None


# The finding tag that names each context (``shadowscan.risk.TAG_WEIGHTS`` scores them).
NEGATIVE_CONTEXT_TAGS: dict[str, str] = {
    "documentation": "docs-only",
    "example-code": "example-code-only",
    "generated-code": "generated-code-only",
}


def may_be_declared(rel: str) -> bool:
    """Whether the ``ci`` profile could declare a coverage gap at ``rel``, whatever its project root.

    The profile declares a gap only under a test, documentation, example or
    generated path (``FilesystemConnector._declared_omission``, which also
    reads the file's project root and ``include_tests``), so a path none of
    them names anywhere in it never holds a declared omission. ``shadowscan
    diff`` reads this to tell which missing findings a declared omission
    could have hidden: a report counts those omissions but does not list them.
    """
    return _is_test_path(rel) or _is_docs_path(rel) or _is_example_path(rel) or _is_generated_path(rel)


def negative_context(rel: str, project_root: str = ".") -> NegativeContext | None:
    """Return the strongest negative context for a file path, or None.

    Documentation and example directories count only inside the file's project
    (below ``project_root``): a directory that is itself a project root holds a
    manifest and is a deployable unit, whatever it is called.
    """
    if _is_generated_path(rel):
        return NegativeContext("generated-code", GENERATED_WEIGHT_SCALE, GENERATED_MAX_CONFIDENCE)
    inner = rel
    if project_root not in ("", ".") and rel.startswith(project_root + "/"):
        inner = rel[len(project_root) + 1 :]
    if _is_docs_path(inner):
        return NegativeContext("documentation", DOCS_WEIGHT_SCALE, DOCS_MAX_CONFIDENCE)
    if _is_example_path(inner):
        return NegativeContext("example-code", EXAMPLE_PATH_WEIGHT_SCALE, EXAMPLE_PATH_MAX_CONFIDENCE)
    return None
