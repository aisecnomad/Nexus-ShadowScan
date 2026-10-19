"""The unverified archive preserves supplied counts without upgrading their status."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from tools.shadowbench450_archive import DEFAULT_DIRECTORY, counts_digest, validate

# Frozen from the original PR #269 counts, excluding withdrawn derived judgments.
ORIGINAL_COUNTS_SHA256 = "b96edb8bc35431245682be396ecd177ad484e9c21093757982f3f20f1044bfba"


def test_archive_preserves_original_counts_without_claiming_a_verified_benchmark() -> None:
    result = validate()
    metrics = json.loads((DEFAULT_DIRECTORY / "metrics.json").read_text())
    assert counts_digest(metrics) == ORIGINAL_COUNTS_SHA256
    assert result["validation"] == "arithmetic-only verification"
    assert result["verification_status"] == "unverified"
    assert result["product_performance_verified"] is False
    assert result["benchmark_executed"] is False


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    for name in ("metrics.json", "manifest.json", "REPORT.md"):
        shutil.copyfile(DEFAULT_DIRECTORY / name, tmp_path / name)
    return tmp_path


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("all_surface", {"tp": 0, "fp": 0, "fn": 268}, "aggregate count mismatch"),
        ("in_scope", {"tp": 999, "fp": 0, "fn": 0}, "scope count exceeds total"),
        ("in_scope", {"tp": True, "fp": 0, "fn": 0}, "nonnegative integer"),
        ("rank", 1, "withdrawn rankings"),
    ],
)
def test_inconsistent_or_overclaimed_observations_fail(
    archive: Path, field: str, value: object, message: str
) -> None:
    path = archive / "metrics.json"
    metrics = json.loads(path.read_text())
    metrics["observations"][0][field] = value
    path.write_text(json.dumps(metrics))
    with pytest.raises(ValueError, match=message):
        validate(archive)


@pytest.mark.parametrize("remove_warning", [False, True])
def test_report_drift_or_removed_warning_fails(archive: Path, remove_warning: bool) -> None:
    path = archive / "REPORT.md"
    text = path.read_text()
    if remove_warning:
        text = text.replace(
            "UNVERIFIED — author-supplied adapter observations; arithmetic checks only.", "Verified"
        )
    else:
        text = text.replace("38 / 4 / 230", "39 / 4 / 229")
    path.write_text(text)
    with pytest.raises(ValueError, match="report"):
        validate(archive)


def test_updated_file_hash_does_not_hide_changed_preserved_counts(archive: Path) -> None:
    path = archive / "metrics.json"
    metrics = json.loads(path.read_text())
    metrics["reported_corpus"]["nearMisses"] += 1
    raw = json.dumps(metrics).encode()
    path.write_bytes(raw)
    manifest_path = archive / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["metrics_sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="preserved count digest"):
        validate(archive)
