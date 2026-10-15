"""Runtime corroboration requires the full device identity and fresh derived state."""

from __future__ import annotations

import json

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.correlation import correlate_lifecycle
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED


def _findings(endpoint_device, runtime_device):
    endpoint = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.inventory",
        kind=Kind.AI_APP,
        title="Installed Claude Code",
        resource=f"endpoint:{endpoint_device}:claude",
        resource_type="ai-app",
        account=endpoint_device,
        frameworks=["coding-agent.claude-code"],
    )
    process = Finding(
        surface=Surface.RUNTIME,
        connector="runtime.processes",
        kind=Kind.RUNTIME_PROCESS,
        title="Running Claude Code",
        resource=f"runtime:{runtime_device}:claude:1",
        resource_type="process",
        account=runtime_device,
        frameworks=["coding-agent.claude-code"],
        tags=["observed-running"],
    )
    return endpoint, process


@pytest.mark.parametrize(
    "runtime_device",
    ["build-01.prod.example.com", "build-01", "build-01.dev.example.net"],
)
def test_same_short_host_does_not_establish_device_identity(runtime_device):
    endpoint, process = _findings("build-01.dev.example.com", runtime_device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" not in endpoint.tags
    assert "lifecycle" not in endpoint.metadata
    assert not endpoint.evidence
    assert "observed-running" in process.tags


@pytest.mark.parametrize(
    "device", [REDACTED, REDACTED.lower(), "build-[REDACTED].example.com", "[ReDaCtEd]-device"]
)
def test_identical_redacted_device_values_do_not_establish_identity(device):
    endpoint, process = _findings(device, device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" not in endpoint.tags
    assert "lifecycle" not in endpoint.metadata
    assert "lifecycle" not in process.metadata
    assert not endpoint.evidence
    assert "observed-running" in process.tags


@pytest.mark.parametrize(
    "endpoint_device,runtime_device",
    [
        ("build-01", "build-01"),
        ("build-01.dev.example.com", "BUILD-01.DEV.EXAMPLE.COM"),
        ("device-8f035a42", "device-8f035a42"),
    ],
)
def test_exact_full_device_identity_establishes_runtime_corroboration(endpoint_device, runtime_device):
    endpoint, process = _findings(endpoint_device, runtime_device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" in endpoint.tags
    assert endpoint.metadata["lifecycle"]["states"] == ["installed", "running"]
    assert any(e.signal == "lifecycle:observed-running" for e in endpoint.evidence)


def test_repeated_pass_removes_endpoint_derived_runtime_tag():
    endpoint, process = _findings("build-01.dev.example.com", "build-01.dev.example.com")
    endpoint.add_tag("installed")
    correlate_lifecycle([endpoint, process])
    assert "observed-running" in endpoint.tags
    correlate_lifecycle([endpoint])
    assert endpoint.tags == ["installed"]
    assert "lifecycle" not in endpoint.metadata
    assert not any(e.signal == "lifecycle:observed-running" for e in endpoint.evidence)
    correlate_lifecycle([process])
    assert process.tags == ["observed-running"]


WINDOW = ("2026-01-02T00:00:00Z", "2026-01-02T01:00:00Z")


@pytest.mark.parametrize(
    "timestamp,status,reason",
    [
        ("2026-01-02T00:30:00Z", "observed-in-window", "timestamped-process-observation"),
        ("2026-01-01T00:00:00Z", "historical", "outside-observation-window"),
        ("2026-01-03T00:00:00Z", "unknown", "future-observation-timestamp"),
        (None, "unknown", "missing-observation-timestamp"),
        ("invalid", "unknown", "missing-observation-timestamp"),
    ],
)
def test_lifecycle_recency_is_explicit_without_promoting_historical_observations(timestamp, status, reason):
    endpoint, process = _findings("build-01", "build-01")
    process.metadata["observed_at"] = timestamp
    before = (endpoint.confidence, endpoint.risk.score)
    correlate_lifecycle([endpoint, process], observation_window=WINDOW, runtime_coverage="export-only")
    assessment = endpoint.metadata["lifecycle_observation"]
    assert assessment["status"] == status and assessment["reason"] == reason
    assert assessment["current_execution"] == "not-established"
    assert assessment["runtime_coverage"] == "export-only"
    assert assessment == endpoint.metadata["lifecycle"]["observation"]
    assert (endpoint.confidence, endpoint.risk.score) == before
    assert all(e.weight == 0 for e in endpoint.evidence)
    assert not any(state in json.dumps(assessment).lower() for state in ('"zombie"', '"ghost"'))


@pytest.mark.parametrize("coverage", ["unknown", "incomplete", "not-collected", "collected", "export-only"])
def test_missing_runtime_never_becomes_inactivity_even_when_collection_succeeded(coverage):
    endpoint, _ = _findings("build-01", "build-01")
    correlate_lifecycle([endpoint], observation_window=WINDOW, runtime_coverage=coverage)
    assessment = endpoint.metadata["lifecycle_observation"]
    assert assessment["status"] == "unknown"
    assert assessment["reason"] == "no-linked-runtime-observation"
    assert assessment["runtime_coverage"] == coverage and assessment["observations"] == []
    assert "lifecycle" not in endpoint.metadata and "observed-running" not in endpoint.tags


def test_lifecycle_repeated_pass_updates_recency_and_never_reuses_prior_processes():
    endpoint, process = _findings("build-01", "build-01")
    process.metadata["observed_at"] = "2026-01-02T00:30:00Z"
    correlate_lifecycle([endpoint, process], observation_window=WINDOW)
    assert endpoint.metadata["lifecycle_observation"]["status"] == "observed-in-window"
    correlate_lifecycle([endpoint], observation_window=WINDOW, runtime_coverage="incomplete")
    assert endpoint.metadata["lifecycle_observation"]["status"] == "unknown"
    assert endpoint.metadata["lifecycle_observation"]["observations"] == []


@pytest.mark.parametrize("window", [None, ("invalid", WINDOW[1]), (WINDOW[1], WINDOW[0])])
def test_lifecycle_without_a_valid_window_does_not_claim_current_observation(window):
    endpoint, process = _findings("build-01", "build-01")
    process.metadata["observed_at"] = "2026-01-02T00:30:00Z"
    correlate_lifecycle([endpoint, process], observation_window=window, runtime_coverage="fabricated")
    assessment = endpoint.metadata["lifecycle_observation"]
    assert assessment["status"] == "unknown" and assessment["window"] is None
    assert assessment["runtime_coverage"] == "unknown"


def test_engine_supplies_real_scan_window_and_offline_collection_status(index, tmp_path):
    source = tmp_path / "processes.json"
    source.write_text(
        json.dumps(
            [{"pid": 1, "host": "build-01", "argv": ["claude"], "observed_at": "2025-01-01T00:00:00Z"}]
        )
    )
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("runtime.processes", {"input": str(source)})]), index
    ).run()
    assert result.findings
    assessment = result.findings[0].metadata["lifecycle_observation"]
    assert assessment["window"]["start"] == result.started_at
    assert assessment["runtime_coverage"] == "export-only"
    assert assessment["status"] == "historical"


def test_lifecycle_process_birth_time_is_not_an_observation_time():
    endpoint, process = _findings("build-01", "build-01")
    process.first_seen = process.last_seen = "2026-01-02T00:30:00Z"
    correlate_lifecycle([endpoint, process], observation_window=WINDOW)
    assert endpoint.metadata["lifecycle_observation"]["status"] == "unknown"


def test_lifecycle_sample_limit_does_not_drop_current_observations():
    from shadowscan.correlation import _lifecycle_observation

    processes = [_findings("build-01", f"build-{n}")[1] for n in range(51)]
    processes.sort(key=lambda f: f.id)
    for process in processes:
        process.metadata["observed_at"] = "2026-01-01T00:00:00Z"
    processes[-1].metadata["observed_at"] = "2026-01-02T00:30:00Z"
    assessment = _lifecycle_observation(processes, WINDOW, "collected")
    assert assessment["status"] == "observed-in-window"
    assert assessment["observation_count"] == 51 and assessment["observations_truncated"]
    assert len(assessment["observations"]) == 50


def test_threshold_never_leaves_lifecycle_observations_linking_omitted_findings(index, tmp_path):
    """Regression (#220 graph review F4): a report must not link to a finding it omits."""
    source = tmp_path / "processes.json"
    source.write_text(
        json.dumps(
            [
                {
                    "hostIdentifier": "dev-laptop-07",
                    "columns": {"pid": "1", "uid": "1000", "cmdline": "/home/dana/.local/bin/claude"},
                    "observed_at": "2026-01-01T00:00:00Z",
                }
            ]
        )
    )
    connectors = [
        ConnectorSpec("endpoint.inventory", {"input": "tests/fixtures/endpoint/inventory.jsonl"}),
        ConnectorSpec("runtime.processes", {"input": str(source)}),
    ]
    complete = Engine(ScanConfig(connectors=connectors), index).run()
    process_ids = {f.id for f in complete.findings if f.connector == "runtime.processes"}
    linked = [f for f in complete.findings if f.metadata.get("lifecycle_observation", {}).get("observations")]
    assert process_ids and any(f.connector == "endpoint.inventory" for f in linked)
    # The runtime finding (confidence 0.85) falls below the threshold; the
    # endpoint configuration (0.96) stays and keeps its observation count.
    result = Engine(ScanConfig(connectors=connectors, min_confidence=0.9), index).run()
    assert result.findings and not any(f.id in process_ids for f in result.findings)
    encoded = json.dumps([f.to_dict() for f in result.findings])
    assert not any(process_id in encoded for process_id in process_ids)
    endpoint = next(
        f for f in result.findings if f.metadata.get("lifecycle_observation", {}).get("observation_count")
    )
    observation = endpoint.metadata["lifecycle_observation"]
    assert observation["observations"] == [] and observation["observations_omitted"] == 1
    assert endpoint.metadata["lifecycle"]["observation"] == observation
