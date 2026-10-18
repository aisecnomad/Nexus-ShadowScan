"""The fuzz targets in tools/fuzz run in the ordinary suite, so the invariants are checked on every change.

The scheduled Fuzz workflow runs the same functions under Atheris, which explores far more inputs. Here
Hypothesis draws inputs, every seed is replayed, and the checks themselves are tested: a check that
cannot fail would turn the fuzz job into a green light that means nothing.
"""

from __future__ import annotations

import importlib
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.signatures.matcher import MatchTimeoutError  # noqa: E402
from shadowscan.utils.redaction import SanitizationLimitError  # noqa: E402
from tools.fuzz import harness, seeds, targets  # noqa: E402
from tools.fuzz.targets import (  # noqa: E402
    LEXERS,
    MAX_INPUT_BYTES,
    PLANTS,
    Cursor,
    InvariantViolation,
    check_lexing,
    check_redaction_record,
    check_redaction_text,
    encode_node,
    planted_text,
    redaction_record_input,
    redaction_text_input,
)

ROOT = Path(__file__).resolve().parents[2]

# Fragments of code, configuration and escapes: random bytes rarely form them, and the lexer and the
# redactor are only interesting on text that does.
FRAGMENTS = [
    *('"', "'", '"""', "'''", "`", "\\", "${", "}", "{", "<<<", "<<~", "#", "//", "/*", "*/", "(*"),
    *("f'", 'f"', 'r#"', '"#', "\n", "\r", "\r\n", " ", "\t", "=", ":", "/", "<", ">", "?>", "<?php"),
    *("%q(", ")", "(", '@"', '$@"', "\\u0022", "\x00", " ", "[REDACTED]", "def f():", "import os"),
    *("password", "token", "Bearer ", "api_key", "eyJ", "--token", "--", "=>", "=begin", "=end", "</div>"),
]
CONTEXT = st.lists(st.sampled_from(FRAGMENTS) | st.text(max_size=6), max_size=40).map("".join)
RAW = st.binary(max_size=MAX_INPUT_BYTES)


def structured(selectors: int) -> st.SearchStrategy[bytes]:
    """Decision bytes followed by code-like text."""
    return st.builds(
        lambda head, text: head + text.encode("utf-8"),
        st.binary(min_size=selectors, max_size=selectors),
        CONTEXT,
    )


# --------------------------------------------------------------------------- the registry


def test_every_target_has_a_name_a_seed_set_and_a_harness_entry() -> None:
    assert set(targets.TARGETS) == set(harness.TARGET_NAMES) == set(seeds.SEEDS)


@pytest.mark.parametrize("name", sorted(targets.TARGETS))
def test_every_seed_passes_its_target(name: str) -> None:
    count = 0
    for seed in seeds.SEEDS[name]():
        targets.TARGETS[name](seed)
        count += 1
    assert count >= 20, "a fuzzer started from a handful of seeds explores very little"


def test_the_repository_fixtures_are_valid_seeds_too() -> None:
    for name in ("lexing", "redaction-text"):
        found = list(seeds.fixture_seeds(name, ROOT / "tests" / "fixtures"))
        assert found, f"no fixture seeds for {name}"
        for seed in found:
            targets.TARGETS[name](seed)


def test_seed_corpus_files_are_unique_and_inside_the_directory(tmp_path: Path) -> None:
    written = seeds.write_corpus("lexing", tmp_path / "corpus")
    files = list((tmp_path / "corpus").iterdir())
    assert written == len(files) > 0
    assert all(path.parent == tmp_path / "corpus" and path.name.startswith("seed-") for path in files)


# --------------------------------------------------------------------------- the encoders


@pytest.mark.parametrize("plant", PLANTS, ids=lambda plant: plant.name)
def test_a_redaction_text_seed_decodes_to_the_planted_text(plant: targets.Plant) -> None:
    cursor = Cursor(redaction_text_input(plant, "left right", cut=128, before=" ", after=","))
    assert cursor.choice(PLANTS) is plant
    assert targets._planted(cursor, plant) == planted_text(plant, "left right", 128, " ", ",")


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        7,
        "text",
        [],
        [None, [1, ["deep"]]],
        {"note": "a", "env": {"id": "b"}, "args": ["--x"]},
    ],
)
def test_encode_node_and_the_decoder_are_inverse(value: object) -> None:
    assert targets._node(Cursor(encode_node(value)), PLANTS[0], 0) == value


def test_a_planted_leaf_decodes_to_the_plant_between_its_separators() -> None:
    data = seeds.encode_planted_leaf("key", before=" ", after=",")
    assert targets._node(Cursor(data), PLANTS[0], 0) == planted_text(PLANTS[0], "key", 128, " ", ",")


def test_a_lexing_seed_names_its_language_and_carries_the_source() -> None:
    cursor = Cursor(seeds.lexing_input(".rs", "let x = 1;"))
    assert cursor.choice(LEXERS) == ("rust", ".rs", False)
    assert cursor.rest() == "let x = 1;"
    assert {entry[1] for entry in LEXERS if entry[0] == "javascript"} >= {".js", ".jsx", ".ts", ".tsx"}


def test_an_isolated_plant_gets_a_line_to_itself_whatever_the_separators() -> None:
    plant = next(plant for plant in PLANTS if plant.isolated)
    assert planted_text(plant, "ab", 128, " ", ",") == "a\n" + plant.text + "\nb"
    format_plant = next(plant for plant in PLANTS if not plant.isolated)
    assert planted_text(format_plant, "ab", 128, " ", ",") == "a " + format_plant.text + ",b"


def test_a_cursor_past_the_end_reads_zero_and_nothing() -> None:
    cursor = Cursor(b"\x05")
    assert (cursor.byte(), cursor.byte(), cursor.text(4), cursor.rest()) == (5, 0, "", "")
    assert Cursor(b"\xff\xfe").rest() == "��"


# --------------------------------------------------------------------------- the invariants hold


@settings(max_examples=150, deadline=None)
@given(RAW | structured(4))
def test_sanitize_text_withholds_planted_credentials(data: bytes) -> None:
    check_redaction_text(data)


@settings(max_examples=100, deadline=None)
@given(RAW | structured(3))
def test_sanitize_withholds_planted_credentials_from_records(data: bytes) -> None:
    check_redaction_record(data)


@settings(max_examples=150, deadline=None)
@given(RAW | structured(1))
def test_the_lexer_returns_in_bounds_sorted_repeatable_spans(data: bytes) -> None:
    check_lexing(data)


# --------------------------------------------------------------------------- the checks can fail


def _text_input(plant: targets.Plant = PLANTS[0]) -> bytes:
    return redaction_text_input(plant, "a\nb\nc")


@pytest.mark.parametrize("plant", PLANTS, ids=lambda plant: plant.name)
def test_a_redactor_that_keeps_the_credential_is_caught(
    monkeypatch: pytest.MonkeyPatch, plant: targets.Plant
) -> None:
    monkeypatch.setattr(targets, "sanitize_text", lambda text: text)
    with pytest.raises(InvariantViolation, match=f"left the {plant.name} credential"):
        check_redaction_text(_text_input(plant))


def test_a_redactor_that_drops_a_line_break_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        targets, "sanitize_text", lambda text: text.replace("\n", "", 1).replace(PLANTS[0].secret, "x")
    )
    with pytest.raises(InvariantViolation, match="number of line breaks"):
        check_redaction_text(_text_input())


def test_a_redactor_that_returns_something_else_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "sanitize_text", lambda text: [text])
    with pytest.raises(InvariantViolation, match="not a str"):
        check_redaction_text(_text_input())


def _record_input() -> bytes:
    return redaction_record_input(PLANTS[0], encode_node({"note": "x"}), "ctx")


def test_a_sanitize_that_keeps_the_credential_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "sanitize", lambda record, **options: record)
    with pytest.raises(InvariantViolation, match="left the github-token credential"):
        check_redaction_record(_record_input())


def test_a_sanitize_that_changes_its_argument_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    def scribble(record: dict, **options: object) -> dict:
        record["note"] = "changed"
        return {}

    monkeypatch.setattr(targets, "sanitize", scribble)
    with pytest.raises(InvariantViolation, match="changed the record"):
        check_redaction_record(_record_input())


def test_a_sanitize_that_returns_non_json_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "sanitize", lambda record, **options: {"x": object()})
    with pytest.raises(InvariantViolation, match="not JSON"):
        check_redaction_record(_record_input())


def _lexing_input() -> bytes:
    return seeds.lexing_input(".py", "x = 'a'\n")


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (([(0, 99)], False), "outside the text"),
        (([(3, 2)], False), "outside the text or runs backwards"),
        (([(4, 5), (1, 2)], False), "not sorted"),
        (([[0, 1]], False), "not a pair of integers"),
        (([(0.0, 1)], False), "not a pair of integers"),
        (((0, 1), False), "not a list"),
        (([], 0), "non-bool"),
    ],
)
def test_a_lexer_that_returns_bad_spans_is_caught(
    monkeypatch: pytest.MonkeyPatch, answer: object, message: str
) -> None:
    monkeypatch.setattr(targets, "noncode_ranges", lambda *args, **options: answer)
    with pytest.raises(InvariantViolation, match=message):
        check_lexing(_lexing_input())


def test_a_lexer_with_two_answers_for_one_text_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter([([], False), ([(0, 1)], False)])
    monkeypatch.setattr(targets, "noncode_ranges", lambda *args, **options: next(answers))
    with pytest.raises(InvariantViolation, match="two answers"):
        check_lexing(_lexing_input())


def test_a_nul_reading_that_leaves_the_text_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "nul_reading_ranges", lambda *args, **options: ([(0, 99)], False))
    with pytest.raises(InvariantViolation, match="NUL-reading span lies outside"):
        check_lexing(seeds.lexing_input(".py", "x = 1\x00\n"))


# --------------------------------------------------------------------------- what may escape


def test_the_documented_fail_closed_errors_are_not_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **options: object) -> object:
        raise SanitizationLimitError("work limit")

    monkeypatch.setattr(targets, "sanitize_text", refuse)
    monkeypatch.setattr(targets, "sanitize", refuse)
    check_redaction_text(_text_input())
    check_redaction_record(_record_input())

    def out_of_budget(*args: object, **options: object) -> object:
        raise MatchTimeoutError("budget")

    monkeypatch.setattr(targets, "noncode_ranges", out_of_budget)
    check_lexing(_lexing_input())


@pytest.mark.parametrize("error", [ValueError, RecursionError, SystemError, IndexError])
def test_any_other_exception_is_a_finding(monkeypatch: pytest.MonkeyPatch, error: type[Exception]) -> None:
    def crash(*args: object, **options: object) -> object:
        raise error("boom")

    monkeypatch.setattr(targets, "sanitize_text", crash)
    with pytest.raises(error):
        check_redaction_text(_text_input())
    monkeypatch.setattr(targets, "noncode_ranges", crash)
    with pytest.raises(error):
        check_lexing(_lexing_input())


def test_a_violation_names_the_input_by_digest_and_never_quotes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "sanitize_text", lambda text: text)
    data = _text_input()
    with pytest.raises(InvariantViolation) as caught:
        check_redaction_text(data)
    message = str(caught.value)
    assert PLANTS[0].text not in message and PLANTS[0].secret not in message
    assert f"{len(data)} bytes" in message and "sha256 " in message


# --------------------------------------------------------------------------- the Atheris entry point


def test_the_harness_says_how_to_install_the_engine_when_it_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = importlib.import_module

    def without_atheris(name: str, *args: object) -> object:
        if name == "atheris":
            raise ModuleNotFoundError("No module named 'atheris'")
        return real(name, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(harness.importlib, "import_module", without_atheris)
    with pytest.raises(SystemExit) as caught:
        harness.run("lexing")
    assert "requirements-fuzz.lock" in str(caught.value) and "--require-hashes" in str(caught.value)


def test_the_harness_rejects_an_unknown_target() -> None:
    with pytest.raises(SystemExit, match="usage: python -m tools.fuzz"):
        harness.main(["no-such-target"])
    with pytest.raises(SystemExit, match="usage: python -m tools.fuzz"):
        harness.main([])


def test_libfuzzer_gets_defaults_for_every_flag_not_given() -> None:
    arguments = harness.libfuzzer_arguments("prog", ["-max_total_time=5", "corpus"])
    assert arguments[0] == "prog" and arguments[-2:] == ["-max_total_time=5", "corpus"]
    assert {"-max_len=8192", "-timeout=30", "-rss_limit_mb=2048"} <= set(arguments)
    artifacts = [argument for argument in arguments if argument.startswith("-artifact_prefix=")]
    assert len(artifacts) == 1 and Path(artifacts[0].split("=", 1)[1]).is_dir()
    assert not Path(artifacts[0].split("=", 1)[1]).is_relative_to(ROOT)


def test_a_flag_that_is_given_replaces_its_default() -> None:
    arguments = harness.libfuzzer_arguments("prog", ["-max_len=100", "-timeout=2", "-artifact_prefix=out/"])
    assert "-max_len=8192" not in arguments and "-timeout=30" not in arguments
    assert [argument for argument in arguments if argument.startswith("-artifact_prefix")] == [
        "-artifact_prefix=out/"
    ]


def test_libfuzzer_reruns_a_command_that_works_from_here() -> None:
    # -minimize_crash, -fork and -jobs start helper processes from the program named first, so it has to
    # be this interpreter running this module, not a label.
    for name in harness.TARGET_NAMES:
        assert shlex.split(harness.command(name)) == [sys.executable, "-m", "tools.fuzz", name]


def test_the_harness_module_does_not_import_the_scanner() -> None:
    # Atheris instruments only modules imported while its hook is active; one imported earlier would be
    # fuzzed blind. The harness imports the targets inside the hook, so it must not import them itself.
    code = "import sys, tools.fuzz.harness; sys.exit(int(any(name.startswith('shadowscan') for name in sys.modules)))"
    assert subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=False).returncode == 0


def test_the_engine_runs_a_target_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("atheris", reason="the fuzzing engine is installed from requirements-fuzz.lock only")
    seeds.write_corpus("lexing", tmp_path / "corpus")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.fuzz",
            "lexing",
            "-runs=300",
            f"-artifact_prefix={tmp_path}/",
            str(tmp_path / "corpus"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
