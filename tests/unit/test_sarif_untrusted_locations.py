"""SARIF artifact locations built from report data that may come from an untrusted merge."""

from __future__ import annotations

import json

import pytest

from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import render


def _finding(*locations: str, root: str = "/repo") -> Finding:
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="Agent",
        resource=f"{root}/Agent",
        resource_type="project",
        frameworks=["framework.langchain"],
    )
    for location in locations:
        finding.add_evidence(Evidence(signal="import", description="import", location=location))
    finding.metadata["scan_root"] = root
    return finding


def _locations(finding: Finding) -> list[dict]:
    result = ScanResult(findings=[finding], stats=[ScanStats(connector="code.filesystem", started_at="t")])
    (res,) = json.loads(render(result, "sarif"))["runs"][0]["results"]
    return res["locations"]


@pytest.mark.parametrize(
    "location",
    [
        "../../../etc/shadow:1",
        "src/../../outside.py:2",
        "//evil.example/share/agent.py:7",
        "\\\\evil\\share\\a.py:1",
    ],
)
def test_locations_outside_the_checkout_or_on_another_host_have_no_artifact(location):
    (location_entry,) = _locations(_finding(location))
    # Only the logical location of the resource remains.
    assert "physicalLocation" not in location_entry
    assert location_entry["logicalLocations"][0]["name"] == "/repo/Agent"


def test_dot_segments_inside_the_checkout_are_resolved():
    (entry,) = _locations(_finding("/repo/src/./lib/../agent.py:3"))
    artifact = entry["physicalLocation"]["artifactLocation"]
    assert artifact == {"uri": "src/agent.py", "uriBaseId": "%SRCROOT%"}


def test_a_root_path_that_climbs_out_has_no_artifact():
    (entry,) = _locations(_finding("/repo/../etc/agent.py:2"))
    assert "physicalLocation" not in entry


def test_absolute_locations_outside_the_root_are_normalized():
    (entry,) = _locations(_finding("/srv/app/../lib/agent.py:2"))
    assert entry["physicalLocation"]["artifactLocation"] == {"uri": "file:///srv/lib/agent.py"}


@pytest.mark.parametrize("line", ["2147483648", "184467440737095516160", "9" * 5000])
def test_line_numbers_beyond_sarif_range_drop_the_region(line):
    (entry,) = _locations(_finding(f"/repo/agent.py:{line}"))
    assert "region" not in entry["physicalLocation"]


def test_largest_valid_line_is_kept():
    (entry,) = _locations(_finding("/repo/agent.py:2147483647"))
    assert entry["physicalLocation"]["region"]["startLine"] == 2147483647


def test_a_lone_surrogate_in_a_location_is_rendered_escaped():
    (entry,) = _locations(_finding("/repo/agent\ud800.py:1"))
    uri = entry["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("agent") and uri.endswith(".py")
