"""Coverage-gap accounting: which unread content invalidates a scan.

A scanner that reports *any* unread byte as a failed scan is not fail-closed in
practice. It fails on ordinary repositories — a dangling symbolic link under
``tests/certs/`` is enough — so operators learn that the incomplete exit code
carries no information and suppress it. The protection then exists only on
paper, which is the outcome strict accounting was meant to prevent.

This module keeps the guarantee while making the signal mean something. A gap
is recorded with the number of entries it costs and the path it occurred at,
and the verdict is taken once, at the end of the connector run, against a
budget:

* A **blinding** gap always marks the scan incomplete, with no budget and no
  appeal: the walk stopped early, an API refused a page, a deadline expired, a
  credential was rejected. The scanner does not know what it did not see, so
  the remainder could be anything.
* A **partial** gap costs a bounded, known amount of coverage: one unreadable
  entry, one unparseable manifest, one link whose target lies outside the tree.
  These accumulate against :attr:`CoveragePolicy.max_gap_ratio`. Within budget
  the scan stays complete and every gap is still counted and, up to
  :data:`MAX_PUBLISHED_GAPS`, listed under ``stats[].coverage.details``; over
  budget the scan is incomplete exactly as before.

Gaps are weighted by whether the path could plausibly hide a deployed agent.
An unreadable file under ``node_modules/`` or ``tests/fixtures/`` is weighted
down, not ignored: it still consumes budget, so a tree with thousands of them
fails. The connector that records a gap decides that relevance when it knows
how it reads the path (``code.filesystem`` reads a test path as source while
``include_tests`` is set); :meth:`CoverageGap.relevance` judges by path
segment for one that passes none. ``strict_coverage`` sets the budget to zero
and restores the original behaviour exactly.

The verdict is taken per *part* of the ledger, one per scan root (and one per
repository for ``code.github`` and ``code.gitlab``), each against its own
examined entries, and never over a summed run: a scan of several roots is
complete only if every root would be complete scanned alone, so the ratio and
the ceiling apply to each root, and N roots may each lose their own
allowance. Summing would let one large clean root dilute a small root's gaps
(a fail-open), and would make an organisation of ordinary repositories fail
together. The published summary combines the parts as
:func:`combine_coverage_summaries` combines an incremental scan's roots: its
``allowance`` is the sum of the parts' allowances.

Nothing here can *hide* a gap. Tolerated gaps are listed in
``stats[].coverage.details`` (the first :data:`MAX_PUBLISHED_GAPS`, with
``details_truncated`` counting the rest), counted in ``gaps`` and
``gap_entries`` beside it, and summarised in one line on the scan stats, so a
reviewer sees what was skipped whether or not it changed the exit code. Only
the JSON report carries ``stats[].coverage``; SARIF, OCSF, Markdown and HTML
carry the verdict line among the diagnostics, which is why it names the JSON
report.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

#: Why a diagnostic leaves a scan incomplete, as ``ScanStats.incomplete_reasons``
#: counts it and each published gap names it (``shadowscan.connectors.base``
#: classifies a diagnostic recorded without one). The categories separate what
#: an operator can act on: a coverage gap in the input (a file too large, a link
#: not followed, content that did not parse), a limit the scanner hit on it, and
#: a failure to reach or read a live source. Defined here so the ledger
#: validator can check a published gap's reason without package imports.
INCOMPLETE_REASONS: tuple[str, ...] = (
    "oversize-file",
    "unresolved-link",
    "unparsed-input",
    "sanitization-limit",
    "timeout",
    "access-denied",
    "upstream-error",
    "analysis-limit",
    "subset-scan",
    "unscanned-input",
    "other",
)

#: Gap kinds that always mark a scan incomplete, whatever the budget.
BLINDING = "blinding"
#: Gap kinds that cost a known, bounded amount of coverage.
PARTIAL = "partial"

#: Default share of examined entries that may be lost before a scan is incomplete.
DEFAULT_MAX_GAP_RATIO = 0.02
#: Weighted entries that may be lost before a scan is incomplete, whatever the ratio allows.
DEFAULT_MAX_GAP_ENTRIES = 100
#: Weight applied to a gap whose path cannot plausibly hold deployed code.
LOW_RELEVANCE_WEIGHT = 0.25
#: Gaps listed individually in the report. Every gap is still counted.
MAX_PUBLISHED_GAPS = 50
#: Declared omissions whose path a connector record lists (``ScanStats.declared_paths``).
#: Every one is still counted; one past the list leaves the rest unlocated.
MAX_DECLARED_PATHS = 200

#: Path segments whose contents are not deployed: dependency trees and tool caches.
#: A gap here is weighted down because the bytes belong to a third party or to a
#: build, not because they are uninteresting.
_VENDORED_SEGMENTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "node_modules",
        "site-packages",
        "third_party",
        "thirdparty",
        "vendor",
        "venv",
    }
)

#: Path segments holding test inputs. An unreadable fixture is a real gap, but a
#: far weaker signal of a hidden *deployed* agent than an unreadable service file.
_TEST_SEGMENTS = frozenset(
    {
        "__fixtures__",
        "__snapshots__",
        "__tests__",
        "fixtures",
        "spec",
        "specs",
        "test",
        "test_data",
        "testdata",
        "tests",
    }
)


def is_vendored_path(path: str) -> bool:
    """Whether a segment of ``path`` names a dependency tree or tool cache (``node_modules``, ``vendor``)."""
    segments = {part.lower() for part in path.replace("\\", "/").split("/") if part}
    return bool(segments & _VENDORED_SEGMENTS)


def validate_max_coverage_gap(value: object) -> float:
    """Return *value* as a gap ratio in [0, 1]; raise :class:`ValueError` otherwise.

    Zero restores strict accounting: every gap marks the scan incomplete.
    ``ConfigValidationError`` subclasses ``ValueError``, so a caller in
    :mod:`shadowscan.config` can let this propagate. This module stays free of
    package imports so the lowest layers can account for coverage.
    """
    message = "max_coverage_gap must be a number between 0 and 1"
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(message)
    ratio = float(value)
    if not math.isfinite(ratio) or not 0.0 <= ratio <= 1.0:
        raise ValueError(message)
    return ratio


_SUMMARY_COUNTS = ("examined", "gaps", "blinding_gaps", "gap_entries")
_SUMMARY_AMOUNTS = ("weighted_gap_entries", "allowance", "max_gap_ratio")
_SUMMARY_KEYS = frozenset(
    (*_SUMMARY_COUNTS, *_SUMMARY_AMOUNTS, "within_budget", "details", "details_truncated")
)
_GAP_KEYS = frozenset({"detail", "path", "kind", "entries", "full_weight", "reason", "relevance"})


def validate_coverage_summary(value: object) -> dict[str, Any] | None:
    """Return *value* if it has the shape :meth:`CoverageLedger.evaluate` publishes, else raise ValueError.

    ``stats.coverage`` crosses a trust boundary twice: a process-mode plugin
    worker returns it, and ``merge`` and ``dashboard`` read it from report
    files. Both readers check every other statistic's type, so this one is
    checked the same way: a forged or malformed ledger is refused rather than
    republished as if the scanner had computed it. None means no gap was
    recorded.
    """
    if value is None:
        return None
    message = "coverage must be a coverage ledger summary"
    if (
        not isinstance(value, dict)
        or not set(value) <= _SUMMARY_KEYS
        or not _SUMMARY_KEYS - {"details_truncated"} <= set(value)
    ):
        raise ValueError(message)
    if any(type(value[key]) is not int or value[key] < 0 for key in _SUMMARY_COUNTS):
        raise ValueError(message)
    for key in _SUMMARY_AMOUNTS:
        amount = value[key]
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int | float)
            or not math.isfinite(amount)
            or amount < 0
        ):
            raise ValueError(message)
    if type(value["within_budget"]) is not bool:
        raise ValueError(message)
    # Within budget means no part lost more than it was allowed, so neither
    # can the parts together: a summary claiming otherwise was not computed here.
    if value["within_budget"] and value["weighted_gap_entries"] > value["allowance"]:
        raise ValueError(message)
    truncated = value.get("details_truncated", 0)
    if type(truncated) is not int or truncated < 0:
        raise ValueError(message)
    details = value["details"]
    if not isinstance(details, list) or len(details) > MAX_PUBLISHED_GAPS:
        raise ValueError(message)
    for gap in details:
        if (
            not isinstance(gap, dict)
            or set(gap) != _GAP_KEYS
            or not isinstance(gap["detail"], str)
            or not isinstance(gap["path"], str)
            or gap["kind"] not in (BLINDING, PARTIAL)
            or type(gap["entries"]) is not int
            or gap["entries"] < 0
            or type(gap["full_weight"]) is not bool
            or gap["reason"] not in INCOMPLETE_REASONS
            or gap["relevance"] not in ("low", "high")
        ):
            raise ValueError(message)
    return value


def coverage_incomplete(summary: dict[str, Any] | None) -> bool:
    """Whether a validated ledger summary says its run is incomplete: over budget or blinded.

    For statistics read back from a report or a plugin worker, whose
    ``incomplete`` flag must not claim a complete run its own ledger refutes.
    """
    return summary is not None and (not summary["within_budget"] or summary["blinding_gaps"] > 0)


def tolerated_gap_entries(summary: Any) -> int:
    """Unread entries a run's budget tolerated: a within-budget summary's ``gap_entries``, else 0."""
    if not isinstance(summary, dict) or summary.get("within_budget") is not True:
        return 0
    entries = summary.get("gap_entries")
    return entries if type(entries) is int and entries > 0 else 0


def combine_coverage_summaries(summaries: Iterable[dict[str, Any] | None]) -> dict[str, Any] | None:
    """One summary for a scan judged in parts: a run's roots or repositories, or an incremental scan's.

    Each part was judged against its own allowance, so the counts and the
    allowances add up and the whole is within budget only if every part was:
    the published ``allowance`` is the sum of the per-root allowances, and may
    exceed the per-root ceiling of :data:`DEFAULT_MAX_GAP_ENTRIES`.
    Only a part that recorded a gap has a summary, so ``examined`` counts the
    entries those verdicts were taken over. Details are kept in order up to
    :data:`MAX_PUBLISHED_GAPS`; every gap is still counted. None when no part
    recorded a gap.
    """
    parts = [summary for summary in summaries if summary is not None]
    if len(parts) <= 1:
        return parts[0] if parts else None
    combined: dict[str, Any] = {key: sum(part[key] for part in parts) for key in _SUMMARY_COUNTS}
    combined["weighted_gap_entries"] = round(sum(part["weighted_gap_entries"] for part in parts), 3)
    combined["allowance"] = round(sum(part["allowance"] for part in parts), 3)
    combined["within_budget"] = all(part["within_budget"] for part in parts)
    # The parts are one connector's roots under its one policy.
    combined["max_gap_ratio"] = parts[0]["max_gap_ratio"]
    combined["details"] = [gap for part in parts for gap in part["details"]][:MAX_PUBLISHED_GAPS]
    if combined["gaps"] > len(combined["details"]):
        combined["details_truncated"] = combined["gaps"] - len(combined["details"])
    return combined


@dataclass(frozen=True, slots=True)
class CoverageGap:
    """One stretch of content the scan could not read.

    ``entries`` is how many entries the gap costs, so a single diagnostic that
    stands for many skipped files (the walk emits one per root) is charged for
    all of them rather than for one.
    """

    detail: str
    path: str = ""
    kind: str = PARTIAL
    entries: int = 1
    #: Charge the full weight whatever the path. For a gap whose danger does
    #: not fall with the path's deployability — content the scanner could not
    #: decode could hide a definition in a fixture as easily as in a service.
    full_weight: bool = False
    #: The ``INCOMPLETE_REASONS`` category the gap is counted under when it
    #: leaves the scan incomplete, decided when it was recorded: ``detail``
    #: names the path, which must not choose the category.
    reason: str = "other"
    #: ``low`` or ``high`` as the recording connector judged the path, which
    #: knows how it reads it; None leaves it to :meth:`relevance`'s segment
    #: list. Published as ``relevance``, not under this name.
    assessed_relevance: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in (BLINDING, PARTIAL):
            raise ValueError(f"unknown coverage gap kind {self.kind!r}")
        if self.entries < 0:
            raise ValueError("coverage gap entries must not be negative")
        if self.reason not in INCOMPLETE_REASONS:
            raise ValueError(f"unknown coverage gap reason {self.reason!r}")
        if self.assessed_relevance not in (None, "low", "high"):
            raise ValueError(f"unknown coverage gap relevance {self.assessed_relevance!r}")

    @property
    def blinding(self) -> bool:
        return self.kind == BLINDING

    def relevance(self) -> str:
        """``low`` when the path cannot plausibly hold a deployed agent, else ``high``.

        The recording connector's own judgement (``assessed_relevance``) when
        it gave one; otherwise any vendored or test segment of the path,
        the file name included, makes it ``low``.
        """
        if self.assessed_relevance is not None:
            return self.assessed_relevance
        segments = {part.lower() for part in self.path.replace("\\", "/").split("/") if part}
        if segments & _VENDORED_SEGMENTS or segments & _TEST_SEGMENTS:
            return "low"
        return "high"

    def weight(self) -> float:
        """Entries charged against the budget, after path weighting."""
        if self.full_weight or self.relevance() == "high":
            return float(self.entries)
        return self.entries * LOW_RELEVANCE_WEIGHT

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        del data["assessed_relevance"]
        data["relevance"] = self.relevance()
        return data


@dataclass(frozen=True, slots=True)
class CoveragePolicy:
    """How much unread content a scan tolerates before it reports itself incomplete."""

    max_gap_ratio: float = DEFAULT_MAX_GAP_RATIO
    max_gap_entries: int = DEFAULT_MAX_GAP_ENTRIES

    @classmethod
    def strict(cls) -> CoveragePolicy:
        """The original behaviour: any gap at all marks the scan incomplete."""
        return cls(max_gap_ratio=0.0, max_gap_entries=0)

    def allowance(self, examined: int) -> float:
        """Weighted entries this scan may lose, given how many it examined."""
        if self.max_gap_ratio <= 0.0:
            return 0.0
        return min(float(self.max_gap_entries), self.max_gap_ratio * max(examined, 0))


#: Parts named in one over-budget verdict line; the rest are counted.
MAX_NAMED_PARTS = 5


@dataclass(slots=True)
class _LedgerPart:
    """The gaps of one scan root or repository and the entries it examined, judged on their own."""

    label: str = ""
    gaps: list[CoverageGap] = field(default_factory=list)
    examined: int = 0

    def evaluate(self, policy: CoveragePolicy) -> tuple[bool, dict[str, Any]]:
        blinding = [gap for gap in self.gaps if gap.blinding]
        weighted = sum(gap.weight() for gap in self.gaps if not gap.blinding)
        allowance = policy.allowance(self.examined)
        over_budget = bool(self.gaps) and weighted > allowance
        # A hostile tree can plant thousands of gaps. Every one is counted
        # against the budget; only the published list is bounded.
        details = [gap.to_dict() for gap in self.gaps[:MAX_PUBLISHED_GAPS]]
        summary: dict[str, Any] = {
            "examined": self.examined,
            "gaps": len(self.gaps),
            "blinding_gaps": len(blinding),
            "gap_entries": sum(gap.entries for gap in self.gaps if not gap.blinding),
            "weighted_gap_entries": round(weighted, 3),
            "allowance": round(allowance, 3),
            "within_budget": not over_budget,
            "max_gap_ratio": policy.max_gap_ratio,
            "details": details,
        }
        if len(self.gaps) > MAX_PUBLISHED_GAPS:
            summary["details_truncated"] = len(self.gaps) - MAX_PUBLISHED_GAPS
        return bool(blinding) or over_budget, summary


def _over_budget(label: str, summary: dict[str, Any], policy: CoveragePolicy) -> str:
    """How far one part went over its own budget, named by its root or repository when it has one."""
    where = f"{label}: " if label else ""
    if summary["allowance"] >= policy.max_gap_entries > 0:
        bound = f"the {policy.max_gap_entries}-entry ceiling"
    else:
        bound = f"the {policy.max_gap_ratio:.1%} budget"
    return (
        f"{where}{summary['gap_entries']} entr(y/ies) unread of {summary['examined']} examined, "
        f"over {bound} ({summary['weighted_gap_entries']:g} weighted of {summary['allowance']:g} allowed)"
    )


@dataclass(slots=True)
class CoverageLedger:
    """Collect gaps during a connector run and decide the verdict once at the end.

    The ledger is kept in *parts*, one per scan root or repository
    (:meth:`begin_part`), each judged against its own examined count and
    allowance. A connector that starts none has a single part, so its run is
    judged as a whole. The run is incomplete when any part is over its budget
    or any gap is blinding: summing the parts would let one large clean root
    dilute a small root's gaps, and would make an organisation of ordinary
    repositories, each within its own budget, fail together. The published
    summary combines the parts as :func:`combine_coverage_summaries` combines
    an incremental scan's roots, so ``allowance`` is the sum of the parts'.
    """

    parts: list[_LedgerPart] = field(default_factory=lambda: [_LedgerPart()])

    @property
    def gaps(self) -> list[CoverageGap]:
        """Every gap recorded so far, in every part."""
        return [gap for part in self.parts for gap in part.gaps]

    @property
    def examined(self) -> int:
        """Entries reached so far, summed across the parts."""
        return sum(part.examined for part in self.parts)

    def begin_part(self, label: str) -> None:
        """Judge the gaps and entries recorded from now on as their own part, named ``label``.

        An opening part that recorded nothing is taken over rather than
        left empty beside the new one.
        """
        current = self.parts[-1]
        if not current.gaps and not current.examined and not current.label:
            current.label = label
        else:
            self.parts.append(_LedgerPart(label))

    def record(self, gap: CoverageGap) -> None:
        self.parts[-1].gaps.append(gap)

    def add_examined(self, delta: int = 1) -> None:
        """Count entries the current part reached. Its roots are summed, not maxed."""
        if delta > 0:
            self.parts[-1].examined += delta

    def note_examined(self, count: int) -> None:
        """Raise the floor of the current part's examined count to *count*.

        For a caller that knows a total rather than a delta; it never lowers
        the count, so mixing it with :meth:`add_examined` cannot shrink the
        denominator and make a gap look worse than it was.
        """
        part = self.parts[-1]
        if count > part.examined:
            part.examined = count

    def weighted_entries(self) -> float:
        return sum(gap.weight() for gap in self.gaps if not gap.blinding)

    def _verdicts(self, policy: CoveragePolicy) -> list[tuple[_LedgerPart, bool, dict[str, Any]]]:
        """Each part that recorded a gap with its verdict; the last part alone when none did."""
        judged = [part for part in self.parts if part.gaps] or self.parts[-1:]
        return [(part, *part.evaluate(policy)) for part in judged]

    def evaluate(self, policy: CoveragePolicy) -> tuple[bool, dict[str, Any]]:
        """Return ``(incomplete, summary)`` for the gaps recorded so far.

        Each part is judged on its own; the summary combines them and is
        published on the scan stats whether or not the scan is incomplete, so
        a tolerated gap is never invisible.
        """
        verdicts = self._verdicts(policy)
        summary = combine_coverage_summaries(summary for _, _, summary in verdicts) or verdicts[0][2]
        return any(incomplete for _, incomplete, _ in verdicts), summary

    def over_budget_gaps(self, policy: CoveragePolicy) -> list[CoverageGap]:
        """The partial gaps of every part over its own budget: the ones that left the run incomplete."""
        return [
            gap
            for part, _, summary in self._verdicts(policy)
            if not summary["within_budget"]
            for gap in part.gaps
            if not gap.blinding
        ]

    def verdict_message(self, policy: CoveragePolicy) -> str | None:
        """One line summarising the budget, or None when it has nothing to add.

        A blinding gap is already reported as an error where it happened, so a
        run whose only gaps are blinding gets no summary: repeating the count
        would be noise on top of the diagnostics that named each one. The line
        exists for what the individual diagnostics cannot say -- that partial
        gaps were tolerated within the budget, or that together they exceeded
        it, in which root or repository.
        """
        partial = [gap for gap in self.gaps if not gap.blinding]
        if not partial:
            return None
        incomplete, summary = self.evaluate(policy)
        lost = summary["gap_entries"]
        if not summary["within_budget"]:
            over = [
                _over_budget(part.label, part_summary, policy)
                for part, _, part_summary in self._verdicts(policy)
                if not part_summary["within_budget"]
            ]
            more = len(over) - MAX_NAMED_PARTS
            named = "; ".join(over[:MAX_NAMED_PARTS]) + (f"; {more} more over budget" if more > 0 else "")
            return f"coverage incomplete: {named}; see stats[].coverage.details"
        if incomplete:
            # Within budget, but a blinding gap condemned the scan anyway.
            # Say what was tolerated so the two are not confused.
            return (
                f"coverage gaps within budget: {lost} entr(y/ies) unread of "
                f"{summary['examined']} examined; the scan is incomplete for another reason"
            )
        # Bracket-free, because SARIF and Markdown escape brackets in a message;
        # and naming the JSON report, the only format that carries the ledger.
        listed = f"the first {MAX_PUBLISHED_GAPS}" if "details_truncated" in summary else "each one"
        return (
            f"coverage gaps tolerated: {lost} entr(y/ies) unread of {summary['examined']} examined, "
            f"within the {policy.max_gap_ratio:.1%} budget; the JSON report lists {listed} under "
            "coverage.details in this connector's stats"
        )
