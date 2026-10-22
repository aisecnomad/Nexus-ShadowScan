"""A sanitized container stays a container of its type.

Two keys of a mapping can read alike once their scheme credentials are
withheld ('SSWS a--auth' and 'SSWS b' are both 'SSWS [REDACTED]' in one
reading of a value, and not in the other). The two readings were paired as
dicts, which keep one member per key, so they did not pair up and the whole
mapping was withheld as one string: agent front matter lost every field and
the scan stayed complete, an agent card's lookups raised, and a finding's
metadata and evidence attributes broke its report. The readings now keep
every member of the source mapping and pair up member by member.
"""

from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize

# Keys that read alike in one reading only: the glued '--auth' is kept beside the
# credential in one reading, and withheld with it in the other.
_COLLIDING = {"SSWS a--auth": 1, "SSWS b": 2, "keep": "evidence"}


def _is_plain(item: Any) -> bool:
    """Whether ``item`` holds only plain dicts, lists and tuples as containers."""
    if isinstance(item, dict):
        return type(item) is dict and all(_is_plain(child) for child in item.values())
    if isinstance(item, (list, tuple)):
        return all(_is_plain(child) for child in item)
    return True


@pytest.mark.parametrize("short", [False, True])
@pytest.mark.parametrize("environment", [False, True])
def test_a_mapping_whose_keys_read_alike_in_one_reading_stays_a_mapping(
    short: bool, environment: bool
) -> None:
    cleaned = sanitize(_COLLIDING, redact_short_secrets=short, env_values_are_secrets=environment)
    # As the established rules copied it: the later member's value under the shared key.
    assert cleaned == {f"SSWS {REDACTED}": 2, "keep": "evidence"}
    assert type(cleaned) is dict


@pytest.mark.parametrize(
    ("value", "path"),
    [
        ([_COLLIDING, "x"], [0]),
        ((_COLLIDING, "x"), [0]),
        ({"meta": _COLLIDING, "tools": ["Read"]}, ["meta"]),
        ({"meta": [{"deep": _COLLIDING}]}, ["meta", 0, "deep"]),
        ({"env": _COLLIDING}, ["env"]),
        ({"env": [_COLLIDING]}, ["env", 0]),
    ],
    ids=["list", "tuple", "nested", "deep", "environment", "environment-list"],
)
def test_a_nested_mapping_whose_keys_read_alike_keeps_its_place_and_type(value: Any, path: list[Any]) -> None:
    cleaned = sanitize(value)
    assert type(cleaned) is type(value)
    assert _is_plain(cleaned)
    nested = cleaned
    for step in path:
        nested = nested[step]
    assert type(nested) is dict
    # An environment mapping's values are withheld whatever their names; its keys stay.
    withheld = path == ["env"]
    assert nested[f"SSWS {REDACTED}"] == (REDACTED if withheld else 2)
    assert nested["keep"] == (REDACTED if withheld else "evidence")
    # The copy is plain data: it serializes, copies and pickles as the input does.
    assert json.loads(json.dumps(cleaned)) is not None
    assert copy.deepcopy(cleaned) == cleaned
    assert pickle.loads(pickle.dumps(cleaned)) == cleaned


def test_siblings_of_colliding_keys_keep_their_containers() -> None:
    record = {
        "SSWS a--auth": {"inner": "x"},
        "SSWS b": ["y"],
        "tools": ["Read", "Grep"],
        "settings": {"model": "sonnet"},
        "pair": ("a", "b"),
    }
    cleaned = sanitize(record)
    assert cleaned["tools"] == ["Read", "Grep"]
    assert cleaned["settings"] == {"model": "sonnet"}
    assert cleaned["pair"] == ("a", "b")
    assert cleaned[f"SSWS {REDACTED}"] == ["y"]


def test_a_member_the_established_reading_drops_is_not_shown() -> None:
    # The established reading copies both keys to one, keeping the later
    # member's value; the other reading keeps both. The earlier member's
    # value, which the established rules dropped, is not shown.
    cleaned = sanitize({"SSWS a--auth": "first-member-value", "SSWS b": "second-member-value"})
    assert cleaned == {f"SSWS {REDACTED}": "second-member-value"}


def test_a_member_the_other_reading_drops_is_not_shown() -> None:
    # The other reading withholds the run that starts the second line of the
    # first key, which then reads as the second key: its dict keeps 'two'.
    # The established reading keeps both; only what both keep is shown.
    record = {"SSWS a\n--x9": "one", "SSWS b\n": "two", "Bearer c--auth": "x", "keep": "evidence"}
    assert sanitize(record) == {f"SSWS {REDACTED}\n": "two", f"Bearer {REDACTED}": "x", "keep": "evidence"}


def test_readings_that_do_not_pair_up_fail_closed() -> None:
    # Two readings of one value always pair up; any that do not cannot be
    # merged safely, and the scan is incomplete rather than a container withheld as text.
    with pytest.raises(SanitizationLimitError):
        redaction._merge_copies(["a"], ["a", "b"])
    with pytest.raises(SanitizationLimitError):
        redaction._merge_copies(
            redaction._Copy([("a", "x")], [0]), redaction._Copy([("a", "x"), ("b", "y")], [0, 1])
        )


def test_copies_compare_by_every_member() -> None:
    one = redaction._Copy([("k", 1), ("k", 2)], [1])
    other = redaction._Copy([("k", 3), ("k", 2)], [1])
    assert dict(one) == dict(other) == {"k": 2}
    assert one != other
    assert one == redaction._Copy([("k", 1), ("k", 2)], [1])
    assert one == {"k": 2}


def test_a_copy_keeps_what_each_step_of_a_dict_keeps() -> None:
    # A step keeps one member per key, at the first one's place and with the
    # last one's value, from the members the step before kept.
    first = redaction._copied({"a": 1, "b": 2, "c": 3}, [("x", 1), ("y", 2), ("x", 3)])
    assert first.view == [2, 1] and list(first.items()) == [("x", 3), ("y", 2)]
    second = redaction._copied(first, [("z", 1), ("z", 2), ("z", 3)])
    # The second step reads the first one's dict: 'y' was kept after 'x' there.
    assert second.view == [1] and dict(second) == {"z": 2}
    assert len(second.members) == 3


def test_a_member_dropped_in_a_later_step_of_the_established_rules_is_not_shown() -> None:
    # The first pass copies both '--x9' keys to one, keeping 'three'; the last
    # pass, which knows '-' as a credential nested under 'password', withholds
    # that key and the '--verbose' one whole, and keeps 'two', the later in
    # its dict. 'three' is the last member of the source, and is not shown.
    record = {
        "Basic abc123\n--x9": "one",
        "Basic T1\n--verbose": "two",
        "Basic b\n--x9": "three",
        "password": ["-"],
        "SSWS a--auth": "x",
        "keep": "evidence",
    }
    cleaned = sanitize(record)
    assert type(cleaned) is dict and cleaned["keep"] == "evidence"
    assert "one" not in cleaned.values() and "three" not in cleaned.values()


def test_finding_metadata_and_evidence_attributes_with_colliding_keys_report() -> None:
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="t",
        resource="r",
        resource_type="t",
    )
    finding.metadata = dict(_COLLIDING)
    evidence = Evidence(signal="s", description="d", location="l", weight=1, attributes=dict(_COLLIDING))
    assert evidence.attributes == {f"SSWS {REDACTED}": 2, "keep": "evidence"}
    finding.add_evidence(evidence)
    finding.recompute_confidence()
    report = finding.to_dict()
    assert report["metadata"]["keep"] == "evidence"
    assert report["evidence"][0]["attributes"] == {f"SSWS {REDACTED}": 2, "keep": "evidence"}


def _definitions(findings: list[Finding]) -> list[dict[str, Any]]:
    return [item for finding in findings for item in finding.metadata.get("agent_definitions", [])]


def test_agent_front_matter_with_colliding_keys_keeps_its_fields(tmp_path, run_connector) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "deployer.md").write_text(
        "---\nname: deployer\ndescription: Deploys the service\ntools: Bash, Read\nmodel: sonnet\n"
        "permissionMode: bypassPermissions\nSSWS a--auth: x\nSSWS b: y\n---\nDeploy.\n",
        encoding="utf-8",
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    [definition] = _definitions(findings)
    assert definition["permissionMode"] == "bypassPermissions"
    assert definition["tools"] == "Bash, Read"
    assert definition["model"] == "sonnet"
    assert definition["description"] == "Deploys the service"


def test_agent_card_with_colliding_keys_is_reported(tmp_path, run_connector) -> None:
    card = {
        "name": "Card Agent",
        "description": "d",
        "url": "https://agent.example.test/a2a",
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "capabilities": {},
        "defaultInputModes": ["text"],
        "defaultOutputModes": ["text"],
        "skills": [{"id": "s", "name": "s", "description": "d", "tags": ["t"]}],
        "SSWS a--auth": "x",
        "SSWS b": "y",
    }
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert [finding.title for finding in findings if finding.kind == Kind.AGENT] == [
        "A2A agent card: Card Agent"
    ]


def test_a_scalar_subclass_is_rebuilt_as_its_standard_type() -> None:
    # Issue #264: the sanitize pass must leave only the exact scalar types the
    # surrender path's detached copy shares, so a subclass is rebuilt by value.
    import datetime
    import enum

    class Flag(enum.IntEnum):
        ON = 3

    class Stamp(datetime.datetime):
        pass

    cleaned = sanitize({"flag": Flag.ON, "at": Stamp(2026, 10, 20, tzinfo=datetime.UTC)})
    assert cleaned == {"flag": 3, "at": datetime.datetime(2026, 10, 20, tzinfo=datetime.UTC)}
    assert type(cleaned["flag"]) is int
    assert type(cleaned["at"]) is datetime.datetime


def test_a_scalar_subclass_keeps_the_value_a_report_shows() -> None:
    # Issue #264 review: the rebuild reads int and float through the base slot, so an
    # overridden __int__/__float__ neither changes the value nor raises; a subclass whose
    # fields do not build its base (pandas NaT) or that carries more than its base keeps
    # (a nanosecond pandas Timestamp) becomes the text a report showed, not an error.
    import datetime

    class Count(int):
        def __int__(self) -> int:
            raise RuntimeError("override must not run")

    class Ratio(float):
        def __float__(self) -> float:
            return -1.0

    class NotATime(datetime.datetime):
        """A stand-in for pandas NaT: a datetime subclass with no real fields."""

        @property
        def year(self) -> float:  # type: ignore[override]
            return float("nan")

        def __str__(self) -> str:
            return "NaT"

    class Precise(datetime.datetime):
        def __str__(self) -> str:
            return super().__str__() + "001"

    exact = datetime.datetime(2026, 10, 20, 12, 30, tzinfo=datetime.UTC)
    cleaned = sanitize(
        {
            "count": Count(5),
            "ratio": Ratio(2.5),
            "missing": NotATime(2026, 1, 1),
            "precise": Precise(2026, 1, 1, 0, 0, 0, 1),
            "exact": exact,
        }
    )
    assert cleaned == {
        "count": 5,
        "ratio": 2.5,
        "missing": "NaT",
        "precise": "2026-01-01 00:00:00.000001001",
        "exact": exact,
    }
    assert [type(cleaned[key]) for key in ("count", "ratio", "missing", "precise")] == [int, float, str, str]
    # An exact datetime is left as it is, not rebuilt on every pass.
    assert redaction._plain(exact) is exact
