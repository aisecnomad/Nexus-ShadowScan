"""Check supplied aggregate arithmetic, never benchmark or product performance."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_DIRECTORY = Path(__file__).resolve().parents[1] / "benchmarks/shadowbench-450/results/2026-10-18"
COUNT_KEYS = ("tp", "fp", "fn")
STATUS = "unverified"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _count(value: Any, label: str) -> int:
    _require(type(value) is int and value >= 0, f"{label}: expected a nonnegative integer")
    return int(value)


def _counts(value: dict[str, Any], label: str) -> None:
    _require(set(value) == set(COUNT_KEYS), f"{label}: expected only TP/FP/FN counts")
    for key in COUNT_KEYS:
        _count(value[key], f"{label}.{key}")


def preserved_counts(metrics: dict[str, Any]) -> dict[str, Any]:
    """Project only the original supplied counts and their adapter identifiers."""
    fields = (
        "adapter_label",
        "all_surface",
        "in_scope",
        "by_surface",
        "reported_top_misses",
        "reported_top_false_alarms",
    )
    return {
        "reported_corpus": metrics["reported_corpus"],
        "observations": [{key: item[key] for key in fields} for item in metrics["observations"]],
    }


def counts_digest(metrics: dict[str, Any]) -> str:
    encoded = json.dumps(preserved_counts(metrics), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def report_table(observations: list[dict[str, Any]]) -> str:
    lines = [
        "| Adapter label | Reported target | Reported version | All-surface TP / FP / FN | "
        "In-scope TP / FP / FN |",
        "|---|---|---|---|---|",
    ]
    for item in observations:
        all_counts = " / ".join(str(item["all_surface"][key]) for key in COUNT_KEYS)
        scope_counts = " / ".join(str(item["in_scope"][key]) for key in COUNT_KEYS)
        lines.append(
            f"| {item['adapter_label']} | {item['reported_product']} | {item['reported_version']} | "
            f"{all_counts} | {scope_counts} |"
        )
    return "\n".join(lines)


def validate(directory: Path = DEFAULT_DIRECTORY) -> dict[str, Any]:
    """Read JSON/Markdown only; execute no fixtures, adapters or third-party code."""
    raw = (directory / "metrics.json").read_bytes()
    metrics = json.loads(raw, object_pairs_hook=_unique_pairs)
    manifest = json.loads((directory / "manifest.json").read_bytes(), object_pairs_hook=_unique_pairs)
    report = (directory / "REPORT.md").read_text(encoding="utf-8")
    _require(
        metrics["verification_status"] == manifest["verification_status"] == STATUS,
        "archive must remain explicitly unverified",
    )
    _require(
        "UNVERIFIED — author-supplied adapter observations; arithmetic checks only." in report,
        "report must disclose unverified observations and arithmetic-only checks",
    )
    corpus = metrics["reported_corpus"]
    for key in ("cases", "positives", "nearMisses", "controls"):
        _count(corpus[key], "corpus." + key)
    surfaces = corpus["bySurface"]
    for surface, counts in surfaces.items():
        _count(counts["cases"], surface + ".cases")
        _count(counts["positives"], surface + ".positives")
    for key in ("cases", "positives"):
        _require(sum(row[key] for row in surfaces.values()) == corpus[key], f"corpus {key} sum mismatch")
    observations = metrics["observations"]
    labels = [item["adapter_label"] for item in observations]
    _require(labels == sorted(set(labels)), "adapter labels must be unique and alphabetical, not ranked")
    _require(len(labels) == manifest["reported_adapters"], "adapter count mismatch")
    for item in observations:
        label = item["adapter_label"]
        _require(
            not {"rank", "tier", "estate_grade", "craft_grade", "all_surface_f1_ci95"} & item.keys(),
            "withdrawn rankings, grades or intervals must not be restored",
        )
        _counts(item["all_surface"], label + ".all_surface")
        _counts(item["in_scope"], label + ".in_scope")
        _require(set(item["by_surface"]) == set(surfaces), label + ": surface set mismatch")
        for surface, counts in item["by_surface"].items():
            _counts(counts, label + "." + surface)
            _require(
                counts["tp"] + counts["fn"] == surfaces[surface]["positives"],
                label + ": positive count mismatch on " + surface,
            )
        for key in COUNT_KEYS:
            _require(
                sum(row[key] for row in item["by_surface"].values()) == item["all_surface"][key],
                label + ": aggregate count mismatch for " + key,
            )
            _require(item["in_scope"][key] <= item["all_surface"][key], label + ": scope count exceeds total")
        for field, total in (("reported_top_misses", "fn"), ("reported_top_false_alarms", "fp")):
            rows = item[field]
            _require(len({row["key"] for row in rows}) == len(rows), label + ": repeated summary key")
            for row in rows:
                _count(row["count"], label + "." + field)
            _require(
                sum(row["count"] for row in rows) <= item["all_surface"][total],
                label + ": summary exceeds total",
            )
    _require(hashlib.sha256(raw).hexdigest() == manifest["metrics_sha256"], "metrics file digest mismatch")
    _require(counts_digest(metrics) == manifest["preserved_counts_sha256"], "preserved count digest mismatch")
    start, end = "<!-- supplied-counts:start -->", "<!-- supplied-counts:end -->"
    _require(report.count(start) == report.count(end) == 1, "expected one supplied-counts table")
    actual_table = report.split(start, 1)[1].split(end, 1)[0].strip()
    _require(actual_table == report_table(observations), "report count table differs from metrics")
    return {
        "validation": "arithmetic-only verification",
        "verification_status": STATUS,
        "adapters_checked": len(observations),
        "product_performance_verified": False,
        "benchmark_executed": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Archive arithmetic check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
