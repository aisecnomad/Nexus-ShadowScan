"""Verify the optional companion checkout and the small local evidence extract.

Initialize explicitly with ``git submodule update --init --depth 1 -- benchmark-suite``.
Verification reads files and Git metadata only; it never runs corpus content.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "tools" / "benchmark_evidence.json"
COMPANION_URL = "https://github.com/aisecnomad/Nexus-ShadowBench.git"
SOURCE_PATHS = {
    "cases": "benchmarks/shadowbench/cases/results/2026-10-11/metrics.json",
    "estate": "benchmarks/shadowbench/estate/results/2026-10-11/metrics.json",
    "code": "benchmarks/shadow-ai-discovery/results/2026-10-09/metrics.json",
    "code_corpus": "benchmarks/shadow-ai-discovery/corpus.json",
}


def extract(suite: Path) -> dict[str, Any]:
    """Keep only the dated fields needed to verify the product guide and chart."""
    raw = {name: (suite / path).read_bytes() for name, path in SOURCE_PATHS.items()}
    documents = {name: json.loads(data) for name, data in raw.items()}
    code = documents["code"]
    labels = {entry["id"]: entry["class"] for entry in documents["code_corpus"]["repos"]}
    negative_incomplete = sum(
        labels[repo] in {"control", "nearmiss"}
        for repo in code["tools"]["shadowscan"]["incomplete_runs"]["repos"]
    )
    migration = json.loads((suite / "MIGRATION.json").read_text(encoding="utf-8"))
    modules = {}
    for entry in migration["files"]:
        name = entry["path"]
        if not name.endswith(".py") or name.endswith("/__init__.py"):
            continue
        if not name.startswith(
            (
                "tools/benchmark/",
                "tools/benchmark_realworld/",
                "tools/discovery_benchmark/",
                "tools/shadowbench/",
                "benchmarks/sab_realworld/",
            )
        ):
            continue
        module = name.removesuffix(".py").replace("/", ".").removesuffix(".__main__")
        if all(part.isidentifier() for part in module.split(".")):
            modules[module] = {"path": name, "sha256": entry["sha256"]}
    modules["tools.verify_migration"] = {
        "path": "tools/verify_migration.py",
        "sha256": hashlib.sha256((suite / "tools/verify_migration.py").read_bytes()).hexdigest(),
    }
    return {
        "schema": 1,
        "source_commit": "0792106b8d2cc09517f7f4ee2eeabf4f8eb8da2d",
        "source_repository": "https://github.com/aisecnomad/Nexus-ShadowScan",
        "migration_manifest_sha256": hashlib.sha256((suite / "MIGRATION.json").read_bytes()).hexdigest(),
        "sources": {
            name: {"path": SOURCE_PATHS[name], "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in raw.items()
        },
        "companion_modules": modules,
        "cases_run": "2026-10-11",
        "cases_tools": {
            name: {key: tool[key] for key in ("coverage", "estate", "in_scope")}
            for name, tool in documents["cases"]["tools"].items()
        },
        "estate": {
            "corpus": documents["estate"]["corpus"],
            "tool": {
                key: documents["estate"]["tools"]["shadowscan"][key] for key in ("version", "entity_level")
            },
        },
        "code": {
            "corpus": code["corpus"],
            "tool": {
                key: code["tools"]["shadowscan"][key]
                for key in ("version", "value_level", "repo_level", "incomplete_runs")
            },
            "incomplete_negatives": negative_incomplete,
        },
    }


def verify_evidence(suite: Path, evidence: Path = EVIDENCE) -> None:
    if json.loads(evidence.read_text(encoding="utf-8")) != extract(suite):
        raise ValueError("local benchmark evidence differs from the pinned companion")


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True, stderr=subprocess.PIPE
    ).strip()


def verify_pin(root: Path = ROOT) -> str:
    """Require the checked-out companion to be the exact gitlink in this checkout."""
    suite = root / "benchmark-suite"
    url = _git(root, "config", "--file", ".gitmodules", "--get", "submodule.benchmark-suite.url")
    entry = _git(root, "ls-files", "--stage", "--", "benchmark-suite").split()
    if url != COMPANION_URL or len(entry) != 4 or entry[0] != "160000" or entry[2] != "0":
        raise ValueError("benchmark-suite must be the reviewed public companion gitlink")
    if suite.is_symlink() or Path(_git(suite, "rev-parse", "--show-toplevel")).resolve() != suite.resolve():
        raise ValueError("initialize benchmark-suite with git submodule update --init")
    if _git(suite, "rev-parse", "HEAD") != entry[1]:
        raise ValueError("benchmark-suite checkout differs from its exact commit pin")
    # Untracked Python files can be collected by pytest or imported by tools.
    # Standard caches remain ignored by the companion's reviewed .gitignore.
    if _git(suite, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("benchmark-suite has modified or untracked files")
    return entry[1]


def main() -> None:
    commit = verify_pin()
    verify_evidence(ROOT / "benchmark-suite")
    print(f"Verified companion {commit} and local benchmark evidence; no corpus executed")


if __name__ == "__main__":
    main()
