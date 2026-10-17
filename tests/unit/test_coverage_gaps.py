"""Coverage-gap budgeting: a bounded gap is tolerated, an unbounded one never is.

The guarantee under test is two-sided. A scan must not report itself complete
when it was blinded, and it must not report itself incomplete because a test
fixture held a dangling symbolic link. Both halves are asserted here, including
that every tolerated gap is still published.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from shadowscan import coverage
from shadowscan.coverage import (
    BLINDING,
    DEFAULT_MAX_GAP_RATIO,
    MAX_PUBLISHED_GAPS,
    CoverageGap,
    CoverageLedger,
    CoveragePolicy,
    combine_coverage_summaries,
    tolerated_gap_entries,
    validate_coverage_summary,
    validate_max_coverage_gap,
)


class TestGapWeighting:
    @pytest.mark.parametrize(
        "path",
        [
            "tests/certs/valid/ca",
            "node_modules/pkg/index.js",
            "vendor/github.com/x/y.go",
            "src/__tests__/helper.ts",
            "a/site-packages/b.py",
            "testdata/sample.bin",
        ],
    )
    def test_vendored_and_test_paths_weigh_less(self, path: str) -> None:
        assert CoverageGap(detail="d", path=path).relevance() == "low"
        assert CoverageGap(detail="d", path=path).weight() == pytest.approx(0.25)

    @pytest.mark.parametrize(
        "path",
        [
            "services/agent/main.py",
            "src/app.py",
            "infra/terraform/main.tf",
            "",
            # 'latest' is not a test segment; a near-miss must stay high.
            "contests/entry.py",
        ],
    )
    def test_deployable_paths_weigh_full(self, path: str) -> None:
        assert CoverageGap(detail="d", path=path).relevance() == "high"
        assert CoverageGap(detail="d", path=path).weight() == pytest.approx(1.0)

    def test_entries_scale_the_weight(self) -> None:
        assert CoverageGap(detail="d", path="src/x", entries=7).weight() == pytest.approx(7.0)

    def test_windows_separators_are_understood(self) -> None:
        assert CoverageGap(detail="d", path=r"pkg\node_modules\x.js").relevance() == "low"

    def test_unknown_kind_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown coverage gap kind"):
            CoverageGap(detail="d", kind="whatever")

    def test_negative_entries_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be negative"):
            CoverageGap(detail="d", entries=-1)

    def test_a_gap_publishes_the_reason_it_was_recorded_with(self) -> None:
        gap = CoverageGap(detail="src/http/403.py: skipped", path="src/http/403.py", reason="unresolved-link")
        assert gap.to_dict()["reason"] == "unresolved-link"
        assert CoverageGap(detail="d").reason == "other"
        with pytest.raises(ValueError, match="unknown coverage gap reason"):
            CoverageGap(detail="d", reason="\x1b[2Jforged")

    def test_the_ledger_validator_checks_each_gap_reason(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(100)
        ledger.record(CoverageGap(detail="d", path="src/x.py", reason="oversize-file"))
        _, summary = ledger.evaluate(CoveragePolicy())
        assert validate_coverage_summary(summary) is summary
        for forged in ("\x1b[2Jforged", "src/x.py", None):
            summary["details"][0]["reason"] = forged
            with pytest.raises(ValueError, match="coverage"):
                validate_coverage_summary(summary)
        del summary["details"][0]["reason"]
        with pytest.raises(ValueError, match="coverage"):
            validate_coverage_summary(summary)


class TestBudget:
    def test_a_lone_fixture_link_in_a_large_tree_is_tolerated(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(1000)
        ledger.record(CoverageGap(detail="link", path="tests/certs/ca"))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        assert incomplete is False
        assert summary["within_budget"] is True
        # Tolerated is not hidden.
        assert summary["gaps"] == 1
        assert summary["details"][0]["path"] == "tests/certs/ca"

    def test_many_gaps_exhaust_the_budget(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(1000)
        for i in range(200):
            ledger.record(CoverageGap(detail="link", path=f"tests/f{i}"))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        # 200 * 0.25 = 50 weighted vs an allowance of 20.
        assert incomplete is True
        assert summary["within_budget"] is False

    def test_one_gap_in_a_deployable_path_of_a_small_tree_fails(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(10)
        ledger.record(CoverageGap(detail="unreadable", path="services/agent.py"))
        incomplete, _ = ledger.evaluate(CoveragePolicy())
        assert incomplete is True

    def test_absolute_cap_binds_on_a_huge_tree(self) -> None:
        """A 2% ratio of a million entries must not tolerate 20,000 unread files."""
        ledger = CoverageLedger()
        ledger.add_examined(1_000_000)
        for i in range(500):
            ledger.record(CoverageGap(detail="x", path=f"src/f{i}.py"))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        assert summary["allowance"] == pytest.approx(100.0)
        assert incomplete is True

    def test_blinding_gap_ignores_the_budget(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(1_000_000)
        ledger.record(CoverageGap(detail="walk stopped", path="tests/x", kind=BLINDING))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        assert incomplete is True
        assert summary["blinding_gaps"] == 1

    def test_strict_policy_restores_the_original_behaviour(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(1_000_000)
        ledger.record(CoverageGap(detail="link", path="tests/certs/ca"))
        incomplete, _ = ledger.evaluate(CoveragePolicy.strict())
        assert incomplete is True

    def test_no_gaps_is_complete_under_every_policy(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(10)
        for policy in (CoveragePolicy(), CoveragePolicy.strict()):
            assert ledger.evaluate(policy)[0] is False

    def test_published_details_are_bounded_but_counting_is_not(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(10_000_000)
        for i in range(MAX_PUBLISHED_GAPS + 25):
            ledger.record(CoverageGap(detail="x", path=f"tests/f{i}"))
        _, summary = ledger.evaluate(CoveragePolicy())
        assert len(summary["details"]) == MAX_PUBLISHED_GAPS
        assert summary["details_truncated"] == 25
        assert summary["gaps"] == MAX_PUBLISHED_GAPS + 25

    def test_examined_sums_across_roots_and_never_shrinks(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(40)
        ledger.add_examined(60)
        assert ledger.examined == 100
        ledger.note_examined(50)
        assert ledger.examined == 100

    def test_parts_judged_apart_combine_into_one_published_summary(self) -> None:
        # Each repository root of an incremental scan is judged on its own; the
        # combined summary keeps every gap counted and the worst verdict.
        summaries = []
        for examined, gaps in ((10_000, 30), (10, 30)):
            ledger = CoverageLedger()
            ledger.add_examined(examined)
            for i in range(gaps):
                ledger.record(CoverageGap(detail="x", path=f"src/f{i}.py"))
            summaries.append(ledger.evaluate(CoveragePolicy())[1])
        combined = combine_coverage_summaries([summaries[0], None, summaries[1]])
        assert validate_coverage_summary(combined) is combined
        assert combined["examined"] == 10_010 and combined["gaps"] == 60
        assert combined["allowance"] == pytest.approx(summaries[0]["allowance"] + summaries[1]["allowance"])
        assert summaries[0]["within_budget"] and not combined["within_budget"]
        assert len(combined["details"]) == MAX_PUBLISHED_GAPS and combined["details_truncated"] == 10
        assert combine_coverage_summaries([None, summaries[0]]) is summaries[0]
        assert combine_coverage_summaries([None, None]) is None

    @staticmethod
    def _part(examined: int, gaps: int, prefix: str, *, blinding: bool = False) -> dict:
        ledger = CoverageLedger()
        ledger.add_examined(examined)
        for i in range(gaps):
            ledger.record(CoverageGap(detail="x", path=f"{prefix}/l{i}.py"))
        if blinding:
            ledger.record(CoverageGap(detail="stopped", path=f"{prefix}/stop", kind=BLINDING))
        return ledger.evaluate(CoveragePolicy())[1]

    def test_a_combined_summary_lists_the_gaps_of_the_parts_that_left_it_incomplete_first(self) -> None:
        # A large root's 55 tolerated gaps took every published slot, so the gaps
        # of the small root the verdict line named were not listed at all.
        big, small = self._part(3_000, 55, "big"), self._part(13, 3, "small")
        combined = combine_coverage_summaries([big, small])
        assert validate_coverage_summary(combined) is combined
        paths = [gap["path"] for gap in combined["details"]]
        assert paths[:3] == ["small/l0.py", "small/l1.py", "small/l2.py"]
        assert len(paths) == MAX_PUBLISHED_GAPS and combined["details_truncated"] == 8
        # A blinded part within its budget left the scan incomplete too.
        blinded = self._part(3_000, 1, "blinded", blinding=True)
        combined = combine_coverage_summaries([big, blinded])
        assert [gap["path"] for gap in combined["details"]][:2] == ["blinded/l0.py", "blinded/stop"]

    def test_a_combined_summary_says_how_its_verdict_divides(self) -> None:
        # 58 weighted of 61.36 allowed beside within_budget false reads as a
        # contradiction unless the summary says one part went over its own.
        big, small = self._part(3_000, 55, "big"), self._part(13, 3, "small")
        combined = combine_coverage_summaries([big, small])
        assert combined["weighted_gap_entries"] < combined["allowance"] and not combined["within_budget"]
        assert (combined["parts"], combined["parts_over_budget"]) == (2, 1)
        # The big root's own budget tolerated its 55 entries; the small one's tolerated none.
        assert combined["tolerated_gap_entries"] == 55 == tolerated_gap_entries(combined)
        both = combine_coverage_summaries([big, self._part(3_000, 2, "other")])
        assert (both["parts"], both["parts_over_budget"], both["tolerated_gap_entries"]) == (2, 0, 57)
        # Combining combined summaries keeps counting parts, not summaries.
        nested = combine_coverage_summaries([combined, both])
        assert (nested["parts"], nested["parts_over_budget"], nested["tolerated_gap_entries"]) == (4, 1, 112)
        assert validate_coverage_summary(nested) is nested
        # A single part publishes none of these keys, and is read as before.
        assert not {"parts", "parts_over_budget", "tolerated_gap_entries"} & set(big)
        assert tolerated_gap_entries(big) == 55 and tolerated_gap_entries(small) == 0

    @pytest.mark.parametrize(
        "forged",
        [
            {"tolerated_gap_entries": 59},
            # Every entry tolerated, yet a part went over its budget.
            {"tolerated_gap_entries": 58},
            {"tolerated_gap_entries": -1},
            {"tolerated_gap_entries": "55"},
            {"parts_over_budget": 0},
            {"parts_over_budget": 3},
            {"parts": True},
        ],
    )
    def test_the_validator_refuses_part_counts_its_summary_refutes(self, forged: dict) -> None:
        combined = combine_coverage_summaries([self._part(3_000, 55, "big"), self._part(13, 3, "small")])
        with pytest.raises(ValueError, match="coverage"):
            validate_coverage_summary({**combined, **forged})

    def test_the_validator_refuses_a_within_budget_summary_that_tolerated_less_than_it_lost(self) -> None:
        combined = combine_coverage_summaries([self._part(3_000, 5, "a"), self._part(3_000, 2, "b")])
        assert combined["within_budget"] and combined["tolerated_gap_entries"] == 7
        for forged in ({"tolerated_gap_entries": 5}, {"parts_over_budget": 1}):
            with pytest.raises(ValueError, match="coverage"):
                validate_coverage_summary({**combined, **forged})


class TestVerdictMessage:
    def test_silent_when_nothing_was_skipped(self) -> None:
        assert CoverageLedger().verdict_message(CoveragePolicy()) is None

    def test_tolerated_gaps_are_announced(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(1000)
        ledger.record(CoverageGap(detail="link", path="tests/x"))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None
        assert "tolerated" in message

    def test_a_truncated_gap_list_is_announced_as_truncated(self) -> None:
        """Past MAX_PUBLISHED_GAPS the report lists only the first ones; the verdict says so."""
        ledger = CoverageLedger()
        ledger.add_examined(10_000_000)
        for i in range(MAX_PUBLISHED_GAPS + 1):
            ledger.record(CoverageGap(detail="link", path=f"tests/f{i}"))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None
        assert f"lists the first {MAX_PUBLISHED_GAPS} under coverage.details" in message
        assert "each one" not in message

    def test_a_blinding_gap_alone_gets_no_summary(self) -> None:
        """It was already reported as an error where it happened."""
        ledger = CoverageLedger()
        ledger.record(CoverageGap(detail="stopped", kind=BLINDING))
        assert ledger.verdict_message(CoveragePolicy()) is None

    def test_a_tolerated_gap_beside_a_blinding_one_is_still_summarised(self) -> None:
        """Otherwise the two reasons for exit 3 would be indistinguishable."""
        ledger = CoverageLedger()
        ledger.add_examined(1000)
        ledger.record(CoverageGap(detail="stopped", kind=BLINDING))
        ledger.record(CoverageGap(detail="link", path="tests/x"))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None
        assert "within budget" in message
        assert "another reason" in message

    def test_an_over_budget_verdict_counts_what_the_other_parts_tolerated(self) -> None:
        ledger = CoverageLedger()
        ledger.begin_part("big")
        ledger.add_examined(3_000)
        for i in range(55):
            ledger.record(CoverageGap(detail="link", path=f"links/l{i}.py"))
        ledger.begin_part("small")
        ledger.add_examined(13)
        for i in range(3):
            ledger.record(CoverageGap(detail="link", path=f"links/l{i}.py"))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None and message.startswith("coverage incomplete: small: 3 entr(y/ies)")
        assert "55 entr(y/ies) tolerated within other roots' own budgets" in message
        # One part alone over its budget tolerated nothing elsewhere.
        alone = CoverageLedger()
        alone.add_examined(13)
        alone.record(CoverageGap(detail="link", path="links/l0.py"))
        assert "tolerated" not in (alone.verdict_message(CoveragePolicy()) or "")

    def test_exceeding_the_budget_is_summarised(self) -> None:
        ledger = CoverageLedger()
        ledger.add_examined(10)
        ledger.record(CoverageGap(detail="unreadable", path="src/agent.py"))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None
        assert "over the" in message and "budget" in message


class TestValidation:
    @pytest.mark.parametrize("value", [0, 0.0, 0.02, 0.5, 1, 1.0])
    def test_accepts_a_ratio(self, value: object) -> None:
        assert 0.0 <= validate_max_coverage_gap(value) <= 1.0

    @pytest.mark.parametrize("value", [-0.1, 1.5, "0.5", None, True, False, float("nan"), float("inf")])
    def test_rejects_anything_else(self, value: object) -> None:
        with pytest.raises(ValueError, match="between 0 and 1"):
            validate_max_coverage_gap(value)

    def test_default_is_small(self) -> None:
        assert 0 < DEFAULT_MAX_GAP_RATIO <= 0.05


class TestEndToEnd:
    """The behaviour the change exists for, through a real scan."""

    @staticmethod
    def _tree(tmp_path, files: int) -> None:
        src = tmp_path / "src"
        src.mkdir()
        for i in range(files):
            (src / f"mod{i}.py").write_text(f"VALUE = {i}\n", encoding="utf-8")

    @staticmethod
    def _dangling_link(tmp_path, rel: str) -> None:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(tmp_path / "does-not-exist", target)

    def _run(self, tmp_path, **config):
        from shadowscan.connectors.base import ConnectorContext
        from shadowscan.connectors.code.filesystem import FilesystemConnector

        ctx = ConnectorContext(config={"paths": [str(tmp_path)], **config})
        connector = FilesystemConnector(ctx)
        connector.run()
        assert ctx.stats is not None
        return ctx.stats

    def test_dangling_fixture_link_no_longer_fails_the_scan(self, tmp_path) -> None:
        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path)
        assert stats.incomplete is False
        assert stats.coverage is not None
        assert stats.coverage["gaps"] == 1
        assert stats.coverage["within_budget"] is True

    def test_the_tolerated_gap_is_still_reported(self, tmp_path) -> None:
        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path)
        assert any("symbolic link" in w for w in stats.warnings)
        assert stats.coverage is not None
        assert stats.coverage["details"][0]["relevance"] == "low"

    def test_strict_coverage_still_fails(self, tmp_path) -> None:
        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path, strict_coverage=True)
        assert stats.incomplete is True

    def test_zero_budget_still_fails(self, tmp_path) -> None:
        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path, max_coverage_gap=0.0)
        assert stats.incomplete is True

    def test_a_flood_of_links_still_fails(self, tmp_path) -> None:
        """Quiet ledger entries must still reach the budget."""
        self._tree(tmp_path, 50)
        for i in range(400):
            self._dangling_link(tmp_path, f"tests/certs/ca{i}")
        stats = self._run(tmp_path)
        assert stats.incomplete is True
        assert stats.coverage is not None
        assert stats.coverage["within_budget"] is False

    def test_every_non_regular_entry_reaches_the_budget(self, tmp_path) -> None:
        """Only the diagnostics stop after the first few; the ledger charges every entry."""
        self._tree(tmp_path, 600)
        for i in range(200):
            (tmp_path / f"svc{i}" / ".mcp.json").mkdir(parents=True)
        stats = self._run(tmp_path)
        assert stats.coverage is not None and stats.coverage["gaps"] == 200
        assert stats.incomplete is True and stats.coverage["within_budget"] is False
        assert len([w for w in stats.warnings if "not a regular file" in w or "not listed" in w]) == 11

    def test_padding_an_mcp_configuration_past_the_size_limit_never_hides_it(self, tmp_path) -> None:
        """Whitespace hides a configuration as well as undecodable bytes do, so neither is budgeted."""
        self._tree(tmp_path, 100)
        mcp = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}'
        (tmp_path / ".mcp.json").write_text(mcp + " " * 1_100_000, encoding="utf-8")
        stats = self._run(tmp_path)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1
        assert any(".mcp.json" in error and "max_file_size" in error for error in stats.errors)
        assert stats.incomplete_reasons == {"oversize-file": 1}

    def test_oversize_configuration_in_discounted_test_code_is_budgeted(self, tmp_path) -> None:
        """As undecodable bytes there are: test code establishes no agent while include_tests is off.

        settings.json is a shared client name, an MCP configuration only by its
        content, so a fixture of that name is discounted test code. A dedicated
        MCP name is not: tests/.mcp.json is read at full weight there too.
        """
        self._tree(tmp_path, 100)
        (tmp_path / "tests" / "fixtures").mkdir(parents=True)
        (tmp_path / "tests" / "fixtures" / "settings.json").write_text(
            "{}" + " " * 1_100_000, encoding="utf-8"
        )
        stats = self._run(tmp_path)
        assert stats.incomplete is False
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 0
        stats = self._run(tmp_path, include_tests=True)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1

    def test_oversize_mcp_configuration_under_a_test_path_is_never_budgeted(self, tmp_path) -> None:
        self._tree(tmp_path, 100)
        (tmp_path / "tests" / "fixtures").mkdir(parents=True)
        (tmp_path / "tests" / "fixtures" / ".mcp.json").write_text("{}" + " " * 1_100_000, encoding="utf-8")
        stats = self._run(tmp_path)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1

    def test_oversize_incidental_content_is_still_budgeted(self, tmp_path) -> None:
        self._tree(tmp_path, 100)
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "export.json").write_text("[" + " " * 1_100_000 + "]", encoding="utf-8")
        stats = self._run(tmp_path)
        assert stats.incomplete is False
        assert stats.coverage is not None
        assert stats.coverage["gaps"] == 1 and stats.coverage["blinding_gaps"] == 0

    @pytest.mark.parametrize(
        ("rel", "config"),
        [
            # The walk excludes vendored directories case-sensitively, so it reads Vendor/ as first-party code.
            ("Vendor/agent/.mcp.json", {}),
            ("Third_Party/agent/.mcp.json", {}),
            # With include_tests, test code is scanned as source.
            ("tests/agent/.mcp.json", {"include_tests": True}),
            # With default_excludes off, vendor/ is scanned as source.
            ("vendor/agent/.mcp.json", {"default_excludes": False}),
        ],
    )
    def test_undecodable_content_the_walk_reads_as_source_is_never_budgeted(
        self, tmp_path, rel, config
    ) -> None:
        self._tree(tmp_path, 100)
        path = tmp_path / rel
        path.parent.mkdir(parents=True)
        path.write_bytes(b'{"mcpServers": {"fs": {"command": "npx"}}}\xff\xfe\x00')
        stats = self._run(tmp_path, **config)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1
        assert any(rel in error and "undecodable" in error for error in stats.errors)

    def test_undecodable_content_in_discounted_test_code_leaves_the_scan_complete(self, tmp_path) -> None:
        self._tree(tmp_path, 100)
        (tmp_path / "tests" / "agent").mkdir(parents=True)
        (tmp_path / "tests" / "agent" / "settings.json").write_bytes(b'{"editor.tabSize": 2}\xff\xfe\x00')
        stats = self._run(tmp_path)
        assert stats.incomplete is False
        assert any(
            "tests/agent/settings.json" in w and "read for credentials only" in w for w in stats.warnings
        )

    def test_undecodable_mcp_configuration_under_a_test_path_is_never_budgeted(self, tmp_path) -> None:
        # A NUL hides a dedicated MCP configuration under tests/ as well as anywhere: in a tree
        # large enough for a 2% budget the gap is still blinding, not tolerated.
        self._tree(tmp_path, 100)
        (tmp_path / "tests" / "agent").mkdir(parents=True)
        (tmp_path / "tests" / "agent" / ".mcp.json").write_bytes(b'{"mcpServers": {}}\xff\xfe\x00')
        stats = self._run(tmp_path)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1

    def test_a_directory_link_to_an_outside_tree_is_never_budgeted(self, tmp_path) -> None:
        """One link can stand for a whole service of agents and MCP servers: no budget bounds it."""
        from click.testing import CliRunner

        from shadowscan.cli import main

        repo, outside = tmp_path / "repo", tmp_path / "outside_agents"
        repo.mkdir()
        self._tree(repo, 200)
        outside.mkdir()
        (outside / ".mcp.json").write_text(
            '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}',
            encoding="utf-8",
        )
        for i in range(50):
            (outside / f"agent{i}.py").write_text(
                "from langchain.agents import AgentExecutor\nAgentExecutor(agent=a, tools=t)\n",
                encoding="utf-8",
            )
        os.symlink(outside, repo / "services")
        stats = self._run(repo)
        assert stats.incomplete is True
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 1
        assert any("symbolic link services" in error for error in stats.errors)
        assert stats.incomplete_reasons == {"unresolved-link": 1}
        result = CliRunner().invoke(main, ["code", str(repo), "--format", "json"])
        assert result.exit_code == 3, result.output

    def test_every_directory_link_is_recorded_and_one_per_root_is_named(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        self._tree(repo, 200)
        for i in range(5):
            (tmp_path / f"outside{i}").mkdir()
            os.symlink(tmp_path / f"outside{i}", repo / f"svc{i}")
        stats = self._run(repo)
        assert stats.coverage is not None and stats.coverage["blinding_gaps"] == 5
        assert len([error for error in stats.errors if "symbolic link" in error]) == 1
        assert stats.incomplete_reasons == {"unresolved-link": 5}

    def test_a_link_to_one_file_outside_the_tree_is_budgeted(self, tmp_path) -> None:
        repo, outside = tmp_path / "repo", tmp_path / "outside"
        repo.mkdir()
        self._tree(repo, 200)
        outside.mkdir()
        (outside / "ca.pem").write_text("certificate\n", encoding="utf-8")
        (repo / "tests" / "certs").mkdir(parents=True)
        os.symlink(outside / "ca.pem", repo / "tests" / "certs" / "ca.pem")
        stats = self._run(repo)
        assert stats.incomplete is False
        assert stats.coverage is not None
        assert stats.coverage["gaps"] == 1 and stats.coverage["blinding_gaps"] == 0

    def test_a_gap_in_deployable_code_is_weighed_in_full(self, tmp_path) -> None:
        self._tree(tmp_path, 30)
        self._dangling_link(tmp_path, "services/agent/link.py")
        stats = self._run(tmp_path)
        assert stats.coverage is not None
        assert stats.coverage["details"][0]["relevance"] == "high"

    def test_the_verdict_and_readme_name_the_published_gap_list(self, tmp_path) -> None:
        """An operator scripting against the key the scan names must find the gaps there."""
        from shadowscan.models import ScanResult

        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path)
        (verdict,) = [warning for warning in stats.warnings if "tolerated" in warning]
        match = re.search(r"the JSON report lists each one under (\S+) in this connector's stats$", verdict)
        assert match is not None
        report = json.loads(ScanResult(stats=[stats]).to_json())
        assert stats.coverage is not None
        published = report["stats"][0]
        for key in match.group(1).split("."):
            published = published[key]
        assert published == stats.coverage["details"]
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
        assert "`stats[].coverage.details`" in readme
        assert "``stats[].coverage.details``" in (coverage.__doc__ or "")
        assert "coverage_gaps" not in readme + (coverage.__doc__ or "")

    def test_the_sarif_verdict_reads_cleanly_and_names_the_json_report(self, tmp_path) -> None:
        """SARIF escapes brackets in a message and has no coverage block of its own."""
        from shadowscan.models import ScanResult
        from shadowscan.reporters.sarif import render_sarif

        self._tree(tmp_path, 200)
        self._dangling_link(tmp_path, "tests/certs/ca")
        stats = self._run(tmp_path)
        log = json.loads(render_sarif(ScanResult(stats=[stats])))
        (invocation,) = log["runs"][0]["invocations"]
        texts = [note["message"]["text"] for note in invocation["toolExecutionNotifications"]]
        (verdict,) = [text for text in texts if "tolerated" in text]
        assert "\\" not in verdict
        assert "the JSON report lists each one under coverage.details" in verdict

    def test_a_clean_tree_publishes_no_coverage_block(self, tmp_path) -> None:
        self._tree(tmp_path, 20)
        stats = self._run(tmp_path)
        assert stats.incomplete is False
        assert stats.coverage is None


class TestDocumentation:
    """What the documentation says about the published ledger matches what is published."""

    ROOT = Path(__file__).resolve().parents[2]

    def test_the_scanning_guide_documents_every_ledger_key(self) -> None:
        guide = (self.ROOT / "docs" / "scanning.md").read_text(encoding="utf-8")
        section = guide.split("### The coverage budget\n", 1)[1].split("\n### ", 1)[0]
        keys = coverage._SUMMARY_KEYS | coverage._GAP_KEYS
        missing = sorted(key for key in keys if f"`{key}`" not in section)
        assert not missing, f"docs/scanning.md does not describe {missing}"
        assert f"The first {MAX_PUBLISHED_GAPS} gaps" in section
        assert "SARIF has no coverage block" in section

    @pytest.mark.parametrize("name", ["README.md", "docs/engineering-log.md"])
    def test_no_document_says_every_tolerated_gap_is_listed(self, name: str) -> None:
        """Only the first MAX_PUBLISHED_GAPS are listed; details_truncated counts the rest."""
        text = " ".join((self.ROOT / name).read_text(encoding="utf-8").split())
        assert "published in full" not in text
        assert f"first {MAX_PUBLISHED_GAPS}" in text
        assert "`details_truncated` count" in text


class TestParts:
    """Each scan root or repository is judged against its own entries, as if scanned alone."""

    @staticmethod
    def _ledger(*parts: tuple[str, int, int]) -> CoverageLedger:
        ledger = CoverageLedger()
        for label, examined, gaps in parts:
            ledger.begin_part(label)
            ledger.add_examined(examined)
            for i in range(gaps):
                ledger.record(CoverageGap(detail="x", path=f"src/f{i}.py", reason="unresolved-link"))
        return ledger

    def test_a_large_clean_part_does_not_dilute_a_small_one(self) -> None:
        ledger = self._ledger(("big", 10_000, 0), ("small", 10, 2))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        assert incomplete and summary["within_budget"] is False
        # Only the part that recorded a gap is in the published summary.
        assert summary["examined"] == 10 and summary["gaps"] == 2
        assert ledger.examined == 10_010 and len(ledger.gaps) == 2
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None and "small: 2 entr(y/ies) unread of 10 examined" in message
        assert "big" not in message

    def test_parts_each_within_budget_stay_complete_and_their_allowances_add(self) -> None:
        ledger = self._ledger(*((f"repo{i}", 100, 1) for i in range(150)))
        incomplete, summary = ledger.evaluate(CoveragePolicy())
        # Summed, 150 entries would pass the 100-entry ceiling.
        assert not incomplete and summary["within_budget"] is True
        assert summary["allowance"] == pytest.approx(150 * 2.0)
        assert ledger.over_budget_gaps(CoveragePolicy()) == []
        assert validate_coverage_summary(summary) is summary

    def test_the_verdict_names_a_bounded_number_of_parts(self) -> None:
        ledger = self._ledger(*((f"repo{i}", 10, 3) for i in range(coverage.MAX_NAMED_PARTS + 3)))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None
        assert "repo0:" in message and f"repo{coverage.MAX_NAMED_PARTS}:" not in message
        assert "3 more over budget" in message
        assert len(ledger.over_budget_gaps(CoveragePolicy())) == 3 * (coverage.MAX_NAMED_PARTS + 3)

    def test_the_ceiling_is_named_when_it_binds(self) -> None:
        ledger = self._ledger(("huge", 1_000_000, 150))
        message = ledger.verdict_message(CoveragePolicy())
        assert message is not None and "100-entry ceiling" in message

    def test_an_unused_opening_part_is_taken_over(self) -> None:
        ledger = CoverageLedger()
        ledger.begin_part("root")
        assert [part.label for part in ledger.parts] == ["root"]
