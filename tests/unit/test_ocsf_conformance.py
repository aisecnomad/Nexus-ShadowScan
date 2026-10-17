"""Every emitted event carries OCSF's required attributes.

The bug this guards against: ``time`` is required by the Detection Finding
class, but an unparseable scan timestamp dropped it, and a validating
pipeline rejects an event missing a required attribute. That path is reachable
in ordinary use — an undated fleet merge sets ``started_at`` to the empty
string — so a whole report could be discarded downstream.

These checks read the vendored requirement manifest rather than restating
attribute names inline, so a schema refresh tightens the tests automatically.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from shadowscan.models import Finding, Kind, ScanResult, Surface
from shadowscan.reporters.ocsf import _OCSF_VERSION, render_ocsf
from tools.ocsf_schema import load


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return load(_OCSF_VERSION)


def _finding(title: str = "an agent") -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=title,
        resource="services/agent",
        resource_type="repo",
    )


def _events(**kwargs: Any) -> list[dict[str, Any]]:
    result = ScanResult(findings=[_finding()], **kwargs)
    return list(json.loads(render_ocsf(result))["events"])


#: Timestamp pairs that reach the reporter in real use. The empty pair is an
#: undated fleet merge; the malformed pair is a merged report whose source
#: carried a non-ISO string, which ``fleet`` passes through as text.
TIMESTAMPS = [
    pytest.param("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", id="dated"),
    pytest.param("2026-01-01T00:00:00Z", "", id="no-finish"),
    pytest.param("", "", id="undated-fleet-merge"),
    pytest.param("not-a-date", "also-not-a-date", id="non-iso"),
    pytest.param("2026-13-45T99:99:99Z", "", id="out-of-range"),
]


class TestRequiredAttributes:
    @pytest.mark.parametrize(("started", "finished"), TIMESTAMPS)
    def test_every_required_attribute_is_present(
        self, schema: dict[str, Any], started: str, finished: str
    ) -> None:
        for event in _events(started_at=started, finished_at=finished):
            missing = [name for name in schema["required"] if name not in event]
            assert missing == [], f"required OCSF attributes absent: {missing}"

    @pytest.mark.parametrize(("started", "finished"), TIMESTAMPS)
    def test_time_is_always_an_integer(self, started: str, finished: str) -> None:
        for event in _events(started_at=started, finished_at=finished):
            assert isinstance(event["time"], int)
            assert not isinstance(event["time"], bool)
            assert event["time"] > 0

    def test_a_substituted_timestamp_is_declared(self) -> None:
        event = _events(started_at="", finished_at="")[0]
        assert event["unmapped"]["time_source"] == "report_render"

    def test_a_parsed_timestamp_is_not_labelled(self) -> None:
        event = _events(started_at="2026-01-01T00:00:00Z", finished_at="2026-01-02T00:00:00Z")[0]
        assert "time_source" not in event["unmapped"]

    def test_a_parsed_timestamp_is_used_rather_than_now(self) -> None:
        event = _events(started_at="2026-01-01T00:00:00Z", finished_at="2026-01-02T00:00:00Z")[0]
        assert event["time"] == 1767312000000


class TestTypesAndEnums:
    @pytest.mark.parametrize(("started", "finished"), TIMESTAMPS)
    def test_attribute_types_match(self, schema: dict[str, Any], started: str, finished: str) -> None:
        kinds: dict[str, type | tuple[type, ...]] = {
            "integer": int,
            "string": str,
            "object": dict,
            "array": list,
        }
        for event in _events(started_at=started, finished_at=finished):
            for name, declared in schema["types"].items():
                if name not in event or event[name] is None:
                    continue
                expected = kinds.get(declared)
                if expected is None:
                    continue
                assert isinstance(event[name], expected), f"{name} is not {declared}"
                if expected is int:
                    assert not isinstance(event[name], bool), f"{name} is a bool, not an integer"

    def test_enumerated_attributes_use_declared_values(self, schema: dict[str, Any]) -> None:
        event = _events(started_at="2026-01-01T00:00:00Z", finished_at="2026-01-02T00:00:00Z")[0]
        for name, allowed in schema["enums"].items():
            if name in event:
                assert event[name] in allowed, f"{name}={event[name]} is outside the declared enum"

    def test_nested_objects_carry_their_required_keys(self, schema: dict[str, Any]) -> None:
        event = _events(started_at="2026-01-01T00:00:00Z", finished_at="2026-01-02T00:00:00Z")[0]
        for key in schema["finding_info_required"]:
            assert key in event["finding_info"]
        for key in schema["metadata_required"]:
            assert key in event["metadata"]
        for key in schema["product_required"]:
            assert key in event["metadata"]["product"]


class TestFixtureHygiene:
    def test_the_vendored_manifest_matches_the_reporter_version(self, schema: dict[str, Any]) -> None:
        assert schema["_provenance"]["ocsf_version"] == _OCSF_VERSION

    def test_time_is_recorded_as_required(self, schema: dict[str, Any]) -> None:
        """The regression this suite exists for: if 'time' leaves the required
        list, the checks above stop testing anything."""
        assert "time" in schema["required"]

    def test_provenance_states_whether_it_was_transcribed(self, schema: dict[str, Any]) -> None:
        # Honesty about the artifact: unlike the SARIF fixture this is not the
        # authoritative document, and the file must keep saying so until a
        # refresh replaces it.
        assert isinstance(schema["_provenance"]["transcribed"], bool)
        assert schema["_provenance"]["source"].startswith("https://schema.ocsf.io/")


def test_an_empty_scan_still_renders_a_valid_document() -> None:
    document = json.loads(render_ocsf(ScanResult(findings=[], started_at="", finished_at="")))
    assert document["events"] == []
    assert document["scan"]["complete"] is False
