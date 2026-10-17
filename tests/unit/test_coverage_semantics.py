"""One decision for every coverage gap: strict accounting, declaration, discount, budget.

Three mechanisms decide when unread content leaves a scan incomplete: the
coverage budget (``shadowscan.coverage``), the test-code discount
(``include_tests`` off) and the ``ci`` profile's declared omissions. Each case
here combines two of them, the way an operator's configuration does, and pins
the documented order (docs/scanning.md, "Strict accounting" and "Coverage
policy"): strict accounting first, then declaration, then the discount, then
the budget, and never a reading in which the scan looks complete while a rule
said it was not.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector

PROVIDERS = [GitHubConnector, GitLabConnector]

# A PNG-like header puts NUL bytes in the first 8 KiB, so the file is binary.
BINARY = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00plain\x00\xff\xfe"
# Duplicate keys: a structured-parsing failure, discounted in test code.
MALFORMED_YAML = "agents: {first: {}}\nagents: {}\n"
# Python 2: source that does not parse, a plain warning in test code.
PYTHON2 = "print 'hello'\n"


def _tree(root: Path, extra: dict[str, bytes | str] | None = None, links: list[str] | None = None) -> Path:
    """A product tree of 61 source files, plus ``extra`` files and dangling ``links``."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("from openai import OpenAI\nclient = OpenAI()\n")
    for i in range(60):
        (root / "src" / f"m{i}.py").write_text(f"x = {i}\n")
    for rel, content in (extra or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    for rel in links or []:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(root / "does-not-exist", path)
    return root


# ------------------------------------------------------------ strict accounting
# strict_coverage and a gap budget of 0 are the same rule: every gap counts,
# none is discounted as test code or declared by the ci profile.
ZERO_BUDGETS = [
    pytest.param({"max_coverage_gap": 0}, id="connector-budget"),
    pytest.param({"_max_coverage_gap": 0.0}, id="scan-wide-budget"),
]


@pytest.mark.parametrize("budget", ZERO_BUDGETS)
@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({"tests/fixtures/a.txt": BINARY}, id="binary-fixture"),
        pytest.param({"tests/fixtures/agents.yaml": MALFORMED_YAML}, id="malformed-fixture"),
        pytest.param({"tests/legacy/test_py2.py": PYTHON2}, id="unparsed-test-source"),
    ],
)
def test_a_zero_budget_counts_test_code_gaps_as_strict_coverage_does(tmp_path, run_connector, budget, extra):
    _tree(tmp_path, extra)
    _, default = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not default.stats.incomplete
    _, strict = run_connector("code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=True)
    assert strict.stats.incomplete
    _, zero = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **budget)
    assert zero.stats.incomplete, "a budget of 0 left a test-code gap uncounted"
    assert zero.stats.incomplete_reasons


STRICT_SETTINGS = [pytest.param({"strict_coverage": True}, id="strict-coverage"), *ZERO_BUDGETS]
# A value the CUSTOM_API_KEY credential rule reports, assembled at run time.
FIXTURE_KEY = "R4nd0m9Qx2" + "Vb7Lp6"


@pytest.mark.parametrize("setting", STRICT_SETTINGS)
def test_strict_accounting_reads_an_undecodable_test_fixture_for_credentials(
    tmp_path, run_connector, setting
):
    # Strict accounting decides how the fixture's gap is recorded, never whether
    # its credentials are read: it must not find fewer than the default does.
    fixture = BINARY + f'\nCUSTOM_API_KEY = "{FIXTURE_KEY}"\n'.encode() + b"\x00\xff"
    _tree(tmp_path, {"tests/fixtures/dump.txt": fixture})
    found, default = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not default.stats.incomplete
    assert [f.metadata.get("path") for f in found if f.kind.value == "secret"] == ["tests/fixtures/dump.txt"]
    found, strict = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **setting)
    assert [f.metadata.get("path") for f in found if f.kind.value == "secret"] == ["tests/fixtures/dump.txt"]
    assert FIXTURE_KEY not in repr([f.to_dict() for f in found])
    # Read first, then counted: the gap is an error naming the read it got.
    assert strict.stats.incomplete
    assert strict.stats.incomplete_reasons == {"unparsed-input": 1}
    assert [e for e in strict.stats.errors if "tests/fixtures/dump.txt" in e] == [
        "code.filesystem: tests/fixtures/dump.txt: binary or undecodable content in analyzable file; "
        "read for credentials only"
    ]


@pytest.mark.parametrize("budget", ZERO_BUDGETS)
def test_a_zero_budget_says_which_diagnostics_are_gaps(tmp_path, run_connector, budget):
    # A budget of 0 lists the gaps the budget charges in stats.coverage, over
    # one verdict line; the rest, test-code gaps the default accounting does
    # not count among them, are diagnostics at the file that must say they
    # are gaps, since each is counted under its reason.
    _tree(
        tmp_path,
        {"tests/fixtures/broken.json": '{"a": \n', "tests/fixtures/agents.yaml": MALFORMED_YAML},
        links=["src/linked.py"],
    )
    _, default = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    [note] = [w for w in default.stats.warnings if "structured checks skipped" in w]
    assert not note.endswith("coverage incomplete")
    _, zero = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **budget)
    assert zero.stats.incomplete
    assert [gap["path"] for gap in zero.stats.coverage["details"]] == ["src/linked.py"]
    assert [e for e in zero.stats.errors if "coverage incomplete: " in e and "over the 0.0% budget" in e]
    [note] = [w for w in zero.stats.warnings if "structured checks skipped" in w]
    assert note.endswith("structured checks skipped; coverage incomplete")
    assert any("tests/fixtures/agents.yaml" in e for e in zero.stats.errors)
    assert zero.stats.incomplete_reasons["unresolved-link"] == 1
    assert zero.stats.incomplete_reasons["unparsed-input"] >= 2


@pytest.mark.parametrize("setting", STRICT_SETTINGS)
def test_profile_ci_is_refused_under_either_spelling_of_strict_accounting(tmp_path, run_connector, setting):
    _tree(tmp_path)
    with pytest.raises(ConnectorError, match="strict accounting"):
        run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile="ci", **setting)


def test_profile_ci_with_a_positive_budget_is_accepted(tmp_path, run_connector):
    _tree(tmp_path)
    _, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, profile="ci", max_coverage_gap=0.1
    )
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("cls", PROVIDERS)
def test_remote_connectors_refuse_profile_ci_under_a_zero_budget_before_fetching(tmp_path, index, cls):
    scope = {"org": "acme"} if cls is GitHubConnector else {"group": "acme"}
    for setting in ({"_max_coverage_gap": 0.0}, {"strict_coverage": True}):
        with pytest.raises(ConnectorError, match="strict accounting"):
            cls(ConnectorContext(config={**scope, "profile": "ci", **setting}, index=index))
    cls(ConnectorContext(config={**scope, "profile": "ci", "_max_coverage_gap": 0.02}, index=index))


@pytest.mark.parametrize("cls", PROVIDERS)
def test_a_zero_budget_counts_a_checkout_test_fixture_gap(tmp_path, run_connector, cls):
    # The nested code.filesystem connector reads the outer connector's budget.
    _tree(tmp_path / "acme__svc", {"tests/fixtures/a.txt": BINARY})
    _, default = run_connector(cls.name, input=str(tmp_path), use_git=False)
    assert not default.stats.incomplete
    _, zero = run_connector(cls.name, input=str(tmp_path), use_git=False, _max_coverage_gap=0.0)
    assert zero.stats.incomplete


def test_the_code_command_refuses_profile_ci_with_a_zero_budget(tmp_path):
    _tree(tmp_path)
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--profile", "ci", "--max-coverage-gap", "0"])
    assert result.exit_code == 1, result.output
    assert "--profile ci and --max-coverage-gap 0 conflict" in result.output
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--profile", "ci", "--max-coverage-gap", "0.5"])
    assert result.exit_code == 0, result.output


# ----------------------------------------------------------- declared omissions
MCP_CONFIG = '{"mcpServers": {"evil": {"command": "npx", "args": ["-y", "@evil/mcp-server"]}}}'
GUESSED_MCP = "mcpServers:\n  evil:\n    command: npx\n"


def test_every_declared_link_is_counted_and_one_per_root_is_named(tmp_path, run_connector):
    _tree(tmp_path, links=[f"tests/certs/c{i}.pem" for i in range(40)])
    _, ci = run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile="ci")
    assert not ci.stats.incomplete
    assert ci.stats.declared_omissions == 40
    assert len([w for w in ci.stats.warnings if "declared omission" in w]) == 1
    # The default profile charges the same 40 entries to the budget.
    _, default = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert default.stats.coverage is not None and default.stats.coverage["gap_entries"] == 40


@pytest.mark.parametrize(
    ("rel", "content"),
    [
        pytest.param("tests/.mcp.json", MCP_CONFIG[:-1], id="mcp-syntax"),
        pytest.param("tests/.mcp.json", MCP_CONFIG[:-1] + "\x00}", id="mcp-nul"),
        pytest.param("tests/CLAUDE.md", "# Rules\nAlways run the tests.\n\x00", id="instructions-nul"),
        pytest.param(
            "docs/.claude/settings.json", '{"permissions": {"allow": ["Bash(*)"]}}\x00', id="settings-nul"
        ),
        # An MCP configuration by its structure only: the parser passes full_weight.
        pytest.param(
            "tests/mcp.yaml", GUESSED_MCP + "  evil:\n    command: npx\n", id="guessed-mcp-duplicate"
        ),
        pytest.param("docs/.mcp.json", MCP_CONFIG + " " * 2_000, id="mcp-oversize"),
    ],
)
def test_profile_ci_never_declares_a_full_weight_file(tmp_path, run_connector, rel, content):
    _tree(tmp_path, {rel: content})
    _, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, profile="ci", max_file_size=1_000
    )
    assert ctx.stats.incomplete, f"profile ci declared the gap in {rel}"
    # Excerpts withheld for a structured-parse failure are not the configuration's gap: the
    # parse runs before the structure says the file is an MCP configuration.
    declared = [w for w in ctx.stats.warnings if "declared omission" in w and "excerpts withheld" not in w]
    assert not declared


# --------------------------------------------------- unread named configuration
# Configuration its name selects is read for what it declares, so however it goes
# unread -- padded past max_file_size, linked to a file the walk does not scan, a
# FIFO in its place -- one rule judges it: blinding, outside discounted test code.
CONFIGURATION_LINKS = [
    pytest.param(".mcp.json", MCP_CONFIG, id="mcp"),
    pytest.param(".claude/settings.json", '{"permissions": {"allow": ["Bash(*)"]}}', id="claude-settings"),
    pytest.param("CLAUDE.md", "# Rules\nRun anything.\n", id="instructions"),
    # Full weight under a test path too, as the discount and the declaration read it.
    pytest.param("tests/e2e/.mcp.json", MCP_CONFIG, id="tests-mcp"),
    pytest.param("tests/CLAUDE.md", "# Rules\nRun anything.\n", id="tests-instructions"),
]


@pytest.mark.parametrize("profile", ["default", "ci"])
@pytest.mark.parametrize(("rel", "content"), CONFIGURATION_LINKS)
def test_a_link_named_like_configuration_to_an_outside_file_fails_closed(
    tmp_path, run_connector, rel, content, profile
):
    outside = tmp_path / "outside" / "target"
    outside.parent.mkdir()
    outside.write_text(content)
    repo = _tree(tmp_path / "repo", links=[])
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).symlink_to(outside)
    _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, profile=profile)
    assert ctx.stats.incomplete, f"a link {rel} to a file outside the tree was budgeted"
    assert ctx.stats.declared_omissions == 0
    assert ctx.stats.coverage is not None and ctx.stats.coverage["blinding_gaps"] == 1
    assert ctx.stats.incomplete_reasons == {"unresolved-link": 1}
    assert any(rel in e and "named like configuration" in e for e in ctx.stats.errors)


@pytest.mark.parametrize("rel", [".mcp.json", ".claude/settings.json", "tests/e2e/.mcp.json"])
def test_a_fifo_named_like_configuration_fails_closed(tmp_path, run_connector, rel):
    _tree(tmp_path)
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(tmp_path / rel)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert ctx.stats.coverage is not None and ctx.stats.coverage["blinding_gaps"] == 1
    assert ctx.stats.incomplete_reasons == {"unscanned-input": 1}


@pytest.mark.parametrize(
    ("rel", "blinding"),
    [
        pytest.param(".mcp.json", True, id="mcp"),
        pytest.param("tests/e2e/.mcp.json", True, id="tests-mcp"),
        pytest.param("deploy/package.json", True, id="manifest"),
        # Discounted test code and incidental content cost one entry each way.
        pytest.param("tests/fixtures/package.json", False, id="fixture-manifest"),
        pytest.param("src/data.json", False, id="incidental"),
    ],
)
def test_a_link_and_an_oversize_copy_of_one_file_are_judged_alike(tmp_path, run_connector, rel, blinding):
    verdicts = []
    for how in ("link", "oversize"):
        repo = _tree(tmp_path / how)
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        if how == "link":
            (repo / rel).symlink_to(tmp_path / "nowhere")
        else:
            (repo / rel).write_text('{"name": "x", "pad": "' + "a" * 2_000 + '"}')
        _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, max_file_size=1_000)
        assert ctx.stats.coverage is not None
        verdicts.append((ctx.stats.coverage["blinding_gaps"] == 1, ctx.stats.incomplete))
    assert verdicts[0] == verdicts[1] == (blinding, blinding)


def _openai_project_key(number: int) -> str:
    """A distinct synthetic OpenAI project-key form, assembled at run time."""
    body = "".join("abcdefghijKLMNOPQRST0123456789"[(number * 7 + i * 11) % 30] for i in range(48))
    tail = "".join("UVWXYZuvwxyz9876543210ABCDEFGH"[(number * 5 + i * 3) % 30] for i in range(20))
    return "sk-" + "proj-" + body + "T3BlbkFJ" + f"{number:02d}" + tail


def test_profile_ci_never_declares_a_fixture_left_unread_for_credentials(tmp_path, run_connector):
    # The size cap, not the profile, stopped the read: the key in the fixture was
    # never read, so the gap is charged as without the profile and listed.
    recorded = '{"k": "' + _openai_project_key(1) + '", "pad": "' + "a" * 3_000 + '"}'
    _tree(tmp_path, {"tests/fixtures/recorded.json": recorded})
    runs = {
        profile: run_connector(
            "code.filesystem", path=str(tmp_path), use_git=False, profile=profile, max_file_size=1_000
        )[1]
        for profile in ("default", "ci")
    }
    ci = runs["ci"]
    assert ci.stats.declared_omissions == 0
    assert not [w for w in ci.stats.warnings if "declared omission" in w]
    assert ci.stats.coverage == runs["default"].stats.coverage
    assert [gap["path"] for gap in ci.stats.coverage["details"]] == ["tests/fixtures/recorded.json"]
    # Without credential detection nothing reads it: skipped with a warning, as without the profile.
    _, off = run_connector(
        "code.filesystem",
        path=str(tmp_path),
        use_git=False,
        profile="ci",
        max_file_size=1_000,
        scan_secrets=False,
    )
    assert off.stats.coverage is None and not off.stats.incomplete


def test_profile_ci_never_declares_notebook_outputs_unread_for_credentials(tmp_path, run_connector):
    import json

    notebook = {
        "cells": [
            {
                "cell_type": "code",
                "source": ["x = 1\n"],
                "metadata": {},
                "outputs": [{"output_type": "stream", "name": "stdout", "text": ["y" * 3_000]}],
                "execution_count": 1,
            }
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    _tree(tmp_path, {"docs/walkthrough.ipynb": json.dumps(notebook)})
    _, ci = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, profile="ci", max_file_size=1_000
    )
    assert ci.stats.declared_omissions == 0
    assert ci.stats.incomplete and ci.stats.incomplete_reasons == {"oversize-file": 1}
    assert any("saved outputs not scanned for credentials" in w for w in ci.stats.warnings)


def test_a_credential_limit_in_test_code_is_never_declared(tmp_path, run_connector):
    keys = "".join(f'OPENAI_KEY_{n} = "{_openai_project_key(n)}"\n' for n in range(8))
    _tree(tmp_path, {"tests/keys_fixture.py": keys})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile="ci")
    assert ctx.stats.incomplete
    assert ctx.stats.declared_omissions == 0
    assert any(
        "tests/keys_fixture.py" in e and "credential evidence incomplete" in e for e in ctx.stats.errors
    )


# ---------------------------------------------------------------- gap relevance
# The connector weighs a gap as it reads the path: a test path is low only while
# include_tests is off, and the test file names the rest of the scan discounts
# (test_*.py, *.test.ts, conftest.py) count as test paths.
@pytest.mark.parametrize(
    "rel",
    [
        "src/agent.test.ts",
        "src/test_client.py",
        "testing/certs/ca.pem",
        "e2e/certs/ca.pem",
        "cassettes/run.json",
    ],
)
def test_a_gap_in_a_test_path_the_scan_discounts_weighs_low(tmp_path, run_connector, rel):
    _tree(tmp_path, links=[rel])
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.coverage is not None
    [gap] = ctx.stats.coverage["details"]
    assert gap["relevance"] == "low"
    assert ctx.stats.coverage["weighted_gap_entries"] == pytest.approx(0.25)


@pytest.mark.parametrize("profile", ["default", "ci"])
def test_a_full_weight_file_under_a_test_path_weighs_in_full(tmp_path, run_connector, profile):
    # The discount and the declaration treat tests/e2e/.mcp.json as an MCP
    # configuration wherever it lies (_full_weight_in_tests); the budget must not
    # weigh its gap as an ordinary fixture's. A directory of that name is the one
    # such gap that stays partial: its contents are walked.
    _tree(tmp_path, {"tests/e2e/.mcp.json/README.txt": "notes\n"})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile=profile)
    assert ctx.stats.coverage is not None and ctx.stats.declared_omissions == 0
    [gap] = ctx.stats.coverage["details"]
    assert (gap["path"], gap["relevance"]) == ("tests/e2e/.mcp.json", "high")
    assert ctx.stats.coverage["weighted_gap_entries"] == pytest.approx(1.0)


def test_a_snapshot_directory_is_not_a_test_path_to_the_budget(tmp_path, run_connector):
    # CoverageGap.relevance's own segment list names __snapshots__; the scan's
    # test-path rule does not, and the budget follows the scan (migration note).
    _tree(tmp_path, links=["web/__snapshots__/view.py"])
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.coverage is not None
    assert [gap["relevance"] for gap in ctx.stats.coverage["details"]] == ["high"]


def test_include_tests_weighs_test_path_gaps_in_full(tmp_path, run_connector):
    # Three links weigh 0.75 against an allowance of 1.24 while test code is
    # discounted, and 3.0 once include_tests makes it source.
    _tree(tmp_path, links=[f"tests/certs/ca{i}.pem" for i in range(3)])
    _, default = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not default.stats.incomplete
    assert {gap["relevance"] for gap in default.stats.coverage["details"]} == {"low"}
    _, included = run_connector("code.filesystem", path=str(tmp_path), use_git=False, include_tests=True)
    assert included.stats.incomplete
    assert {gap["relevance"] for gap in included.stats.coverage["details"]} == {"high"}
    assert included.stats.coverage["weighted_gap_entries"] == pytest.approx(3.0)


@pytest.mark.parametrize("include_tests", [False, True])
def test_a_vendored_gap_weighs_low_whatever_include_tests(tmp_path, run_connector, include_tests):
    _tree(tmp_path, links=["vendor/pkg/client.py"])
    _, ctx = run_connector(
        "code.filesystem",
        path=str(tmp_path),
        use_git=False,
        default_excludes=False,
        include_tests=include_tests,
    )
    assert ctx.stats.coverage is not None
    assert [gap["relevance"] for gap in ctx.stats.coverage["details"]] == ["low"]


def test_a_gap_recorded_without_a_relevance_keeps_the_segment_rule():
    from shadowscan.coverage import CoverageGap

    assert CoverageGap(detail="d", path="tests/x").relevance() == "low"
    assert CoverageGap(detail="d", path="src/agent.test.ts").relevance() == "high"
    assessed = CoverageGap(detail="d", path="tests/x", assessed_relevance="high")
    assert assessed.relevance() == "high" and assessed.weight() == 1.0
    # The published shape is unchanged: the judgement is published as ``relevance``.
    assert set(assessed.to_dict()) == {
        "detail",
        "path",
        "kind",
        "entries",
        "full_weight",
        "reason",
        "relevance",
    }
    with pytest.raises(ValueError, match="relevance"):
        CoverageGap(detail="d", assessed_relevance="medium")


# ------------------------------------------------------- discounted test code
# A gap in test code whose evidence is discounted is charged to the budget at a
# quarter weight (undecodable bytes at a whole entry): a few leave the scan
# complete, a tree seeded with them does not, and every one is listed.
@pytest.mark.parametrize(
    ("name", "content"),
    [
        pytest.param("tests/fixtures/agents{}.yaml", MALFORMED_YAML, id="malformed"),
        pytest.param("tests/fixtures/attachment{}.txt", BINARY, id="binary"),
    ],
)
def test_a_tree_seeded_with_discounted_fixtures_exhausts_the_budget(tmp_path, run_connector, name, content):
    _tree(tmp_path, {name.format(i): content for i in range(200)})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete, "200 unreadable fixtures, three quarters of the tree, left the scan complete"
    assert ctx.stats.coverage is not None and ctx.stats.coverage["within_budget"] is False
    assert ctx.stats.coverage["gaps"] >= 200


def test_a_few_discounted_fixtures_are_listed_and_tolerated(tmp_path, run_connector):
    # 160 entries allow 3.2 weighted entries; these gaps weigh 1.75.
    _tree(
        tmp_path,
        {
            **{f"lib/part{i}.py": f"y = {i}\n" for i in range(96)},
            "tests/fixtures/agents.yaml": MALFORMED_YAML,
            "tests/legacy/component.js": "const A = () => <p>src/*.js files</p>;\nconst s = `open\n",
            "tests/fixtures/attachment.txt": BINARY,
        },
    )
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    coverage = ctx.stats.coverage
    assert coverage is not None and coverage["within_budget"] is True
    by_path: dict[str, list[dict]] = {}
    for gap in coverage["details"]:
        by_path.setdefault(gap["path"], []).append(gap)
    assert set(by_path) == {
        "tests/fixtures/agents.yaml",
        "tests/legacy/component.js",
        "tests/fixtures/attachment.txt",
    }
    assert all("discounted evidence" in gap["detail"] for gaps in by_path.values() for gap in gaps)
    assert all(gap["relevance"] == "low" for gaps in by_path.values() for gap in gaps)
    # The binary fixture costs a whole entry; the others a quarter each.
    [binary] = by_path["tests/fixtures/attachment.txt"]
    assert binary["full_weight"] is True
    assert not any(gap["full_weight"] for gap in by_path["tests/fixtures/agents.yaml"])


# ------------------------------------------------------------ tolerated gaps
# A complete scan whose budget tolerated unread entries says so in its summary,
# the table banner and the exit-3 line, as a profile scan's declared omissions do.
def test_the_summary_counts_the_gaps_a_budget_tolerated(tmp_path, run_connector):
    from shadowscan.models import ScanResult
    from shadowscan.reporters.table import _header

    _tree(tmp_path, links=["tests/certs/ca.pem"])
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    result = ScanResult(stats=[ctx.stats])
    summary = result.summary()
    assert summary["complete"] is True
    assert summary["tolerated_gaps"] == 1 and summary["declared_omissions"] == 0
    assert "1 tolerated coverage gaps" in _header(result).plain


def test_an_over_budget_run_tolerated_nothing(tmp_path, run_connector):
    from shadowscan.models import ScanResult

    _tree(tmp_path, links=[f"src/link{i}.py" for i in range(10)])
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert ScanResult(stats=[ctx.stats]).summary()["tolerated_gaps"] == 0


def test_a_root_within_its_budget_keeps_its_tolerated_gaps_when_another_goes_over(tmp_path):
    # The big root's own budget tolerated its three links; the small root went
    # over its own. summary.tolerated_gaps read only the combined flag and said 0,
    # and incomplete_reasons counts only the small root, so the big root's gaps
    # reached no counter; scanned alone, the big root reports them.
    import json

    big = _tree(tmp_path / "big", links=[f"certs/c{i}.pem" for i in range(3)])
    for i in range(140):
        (big / "src" / f"x{i}.py").write_text(f"y = {i}\n")
    small = tmp_path / "small"
    (small / "src").mkdir(parents=True)
    for i in range(10):
        (small / "src" / f"m{i}.py").write_text(f"x = {i}\n")
    for i in range(3):
        os.symlink(small / "nowhere", small / f"l{i}.py")
    result = CliRunner().invoke(main, ["code", str(big), str(small), "--no-incremental", "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["incomplete_reasons"] == {"unresolved-link": 3}
    assert report["summary"]["tolerated_gaps"] == 3
    coverage = report["stats"][0]["coverage"]
    assert (coverage["parts"], coverage["parts_over_budget"], coverage["tolerated_gap_entries"]) == (2, 1, 3)
    # The gaps the verdict line points to come first in the published details.
    assert [gap["path"] for gap in coverage["details"]][:3] == ["l0.py", "l1.py", "l2.py"]
    assert "3 coverage gap(s) within budget did not count" in result.stderr
    alone = CliRunner().invoke(main, ["code", str(big), "--no-incremental", "--format", "json"])
    assert alone.exit_code == 0 and json.loads(alone.stdout)["summary"]["tolerated_gaps"] == 3


def test_the_exit_3_line_counts_tolerated_gaps_beside_declared_omissions(tmp_path):
    import json

    good, bad = _tree(tmp_path / "good", links=["tests/certs/ca.pem"]), tmp_path / "bad"
    _tree(bad, {"src/agent.py": b"import os\x00\n"})
    result = CliRunner().invoke(main, ["code", str(good), str(bad), "--format", "json"])
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)["summary"]["tolerated_gaps"] == 1
    assert "1 coverage gap(s) within budget did not count" in result.stderr


# --------------------------------------------------------------------- reasons
# The conditions #254, #256 and #257 added carry their own reason, so neither the
# category "other" nor a scanned path (src/http/, permissions/, tls_config/)
# describes them in summary.incomplete_reasons and on the exit-3 line.
@pytest.mark.parametrize("rel", ["src/keys.py", "src/http/keys.py", "src/permissions/keys.py"])
def test_a_credential_limit_is_an_analysis_limit_wherever_it_lies(tmp_path, run_connector, rel):
    keys = "".join(f'OPENAI_KEY_{n} = "{_openai_project_key(n)}"\n' for n in range(8))
    _tree(tmp_path, {rel: keys})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete_reasons == {"analysis-limit": 1}


@pytest.mark.parametrize("rel", ["src/agent_cookie.py", "src/tls_config/http_agent.py"])
def test_a_refused_coding_cookie_is_unparsed_input(tmp_path, run_connector, rel):
    _tree(tmp_path, {rel: "# -*- coding: utf-16 -*-\nimport os\n"})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert ctx.stats.incomplete_reasons == {"unparsed-input": 1}


def test_withheld_excerpts_of_a_document_that_did_not_parse_are_unparsed_input(tmp_path, run_connector):
    _tree(tmp_path, {"tests/fixtures/agents.yaml": MALFORMED_YAML})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=True)
    assert set(ctx.stats.incomplete_reasons) == {"unparsed-input"}


def test_a_git_lfs_pointer_is_unscanned_input(tmp_path, run_connector):
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 12345\n"
    _tree(tmp_path, {"src/http/model_config.json": pointer})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete_reasons == {"unscanned-input": 1}


def test_ebpf_records_it_could_not_read_are_unparsed_input(tmp_path, run_connector):
    import json

    export = tmp_path / "http_permissions_events.jsonl"
    export.write_text(json.dumps({"kind": "unknown", "payload": {"x": 1}}) + "\n")
    _, ctx = run_connector("endpoint.ebpf", input=str(export))
    assert ctx.stats.incomplete
    assert ctx.stats.incomplete_reasons == {"unparsed-input": 1}


def test_include_tests_keeps_a_binary_test_fixture_a_gap(tmp_path, run_connector):
    # With include_tests, test code is source: undecodable bytes there are blinding, as in src/.
    _tree(tmp_path, {"tests/fixtures/a.txt": BINARY})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, include_tests=True)
    assert ctx.stats.incomplete
    assert ctx.stats.coverage is not None and ctx.stats.coverage["blinding_gaps"] == 1
