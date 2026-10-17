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


@pytest.mark.parametrize(
    "setting",
    [
        pytest.param({"strict_coverage": True}, id="strict-coverage"),
        *ZERO_BUDGETS,
    ],
)
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


def _openai_project_key(number: int) -> str:
    """A distinct synthetic OpenAI project-key form, assembled at run time."""
    body = "".join("abcdefghijKLMNOPQRST0123456789"[(number * 7 + i * 11) % 30] for i in range(48))
    tail = "".join("UVWXYZuvwxyz9876543210ABCDEFGH"[(number * 5 + i * 3) % 30] for i in range(20))
    return "sk-" + "proj-" + body + "T3BlbkFJ" + f"{number:02d}" + tail


def test_a_credential_limit_in_test_code_is_never_declared(tmp_path, run_connector):
    keys = "".join(f'OPENAI_KEY_{n} = "{_openai_project_key(n)}"\n' for n in range(8))
    _tree(tmp_path, {"tests/keys_fixture.py": keys})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile="ci")
    assert ctx.stats.incomplete
    assert ctx.stats.declared_omissions == 0
    assert any(
        "tests/keys_fixture.py" in e and "credential evidence incomplete" in e for e in ctx.stats.errors
    )
