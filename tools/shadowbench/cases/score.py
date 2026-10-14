"""Score stored runs against the corpus: entity-level and case-level metrics per tool and surface.

``python -m tools.shadowbench.cases score --corpus corpus.json --results results/ --out metrics.json``
(``--force`` scores results the manifest does not vouch for, and records each override)

Inputs. Every tool is scored on every case of the corpus. The results
manifest must name the SHA-256 of the corpus file being scored: case ids are
positional, so results recorded against another corpus (another seed, an
edited rubric) would be scored against the wrong truth. Each ``<tool>.jsonl``
must belong to a tool the manifest records as run (the runner never clears its
output directory, and ``--only`` rewrites the manifest with the tools it ran,
so files left from another run must not be scored), the row statuses in the
file must add up to the counts the manifest recorded for that tool (a
truncated or missing file does not), and the file's SHA-256 must be the
``rows_sha256`` the manifest recorded for it (an edited or swapped file is
not). Each of these is refused unless ``--force`` is given, and a forced score
records every override. A manifest written before the runner recorded digests,
the committed 2026-10-11 run's among them, binds its rows only by their status
counts, which another run of the same tool on the same corpus can match; such
tools are listed in ``rows_unbound``. A row with a
status other than ``ok``, ``error`` or ``unsupported``, a second row for the
same case, a row for a case the corpus does not have, a row whose tool is not
the file's, a row whose surface, modality, family, label or difficulty
disagrees with its case, an ``out_of_taxonomy`` count that is not a
non-negative integer or sits on a row outside the code surface, and an
``unsupported`` row on a (surface, modality) where the same tool has ``ok`` or
``error`` rows (the runner decides support per surface and modality) are
refused, ``--force`` or not. A case with no row counts as an ``error`` and is
also reported as missing, unless the tool does not run that case's surface and
modality: its other rows there are ``unsupported``, or it has none there and
its adapter does not declare that pair. The runner writes an ``unsupported``
row for every such case, so a run of some surfaces or cases (``--surfaces``,
``--cases``) left out only rows that would have been ``unsupported``, and such
a missing row counts as ``unsupported``. A tool with no loaded adapter declares
nothing, so its missing rows stay errors.

Matching. A reported key equal to a tolerated key is neither credited nor
penalized. Otherwise it matches an expected or decoy key when they are equal,
or, for ``artifact:`` keys, when the reported path lies inside the expected or
decoy directory (a tool that cites a file in Claude Code's ``.claude``
directory has found it). A reported ancestor directory of an expected file is
never a match: the rubric lists the directories a tool may name instead as
tolerated. Reported keys are de-duplicated. A reported key that matches
nothing expected or tolerated is a false positive; when it matches a decoy it
also counts against specificity.

Code surface. Truth there is ``<category>:<value>`` facts from
``tools.discovery_benchmark.taxonomy``. A reported code key that is not such a
fact (for example a file path an adapter could not map) is out of taxonomy:
neither a true nor a false positive, and counted per tool. An adapter that
drops such hits instead records how many in the row's ``out_of_taxonomy``,
and they count exactly as keys passed on would. At case level an
out-of-taxonomy report earns a positive case nothing and makes a negative case
a false alarm, since the tool alarmed on a repository with nothing to find.
The rule is the same for every tool.

Rules. An ``error`` row (crash, timeout, unreadable output, missing row) is
never a correct outcome: every expected entity counts as missed, its decoys
count against specificity (they are not true negatives, and are not reported
false positives either), a positive case counts as missed and a negative case
as a false alarm. An incomplete run (an ``ok`` row the tool flagged as not
having read everything, such as ShadowScan exit 3) keeps the true and false
positives it reported but never earns a true negative: its unhit decoys stay
in the specificity denominator without counting as true negatives, and a
negative case it scanned incompletely counts as a false alarm, as an error
does. A positive case it found still counts as found. Incomplete rows are also
counted separately. An ``unsupported`` row is excluded from in-scope metrics
and counted as missed in estate recall.

Withheld decoys. An adapter that converts a case's input for its tool may
declare, per (surface, modality), the key prefixes of decoys whose records
its conversion never passes on (``withheld_decoys``; ShadowScan's adapter
does not convert AWS IAM roles). Such a decoy is left out of that tool's
specificity and agent false-alarm denominators, whatever the row's status,
unless the tool reports it anyway, which then counts against the tool like
any other decoy hit; the count left out is reported as ``decoys_withheld``. A
complete ``ok`` row on a negative case whose every decoy was withheld, and
that reports no false positive and nothing out of taxonomy, was shown nothing
it could reject: it is
left out of the tool's case-level negatives (``case.negatives_withheld``)
and of the paired comparison. The declarations come from the adapter
registry; an adapter module that does not load is refused unless ``--force``,
since what it withholds is unknown. A tool without an adapter withholds
nothing.

Case level. A positive case is found when the tool reports at least one
expected entity; a negative case is a false alarm when the tool reports at
least one false positive or anything out of taxonomy, and is correct only on a
complete ``ok`` run. Case recall, specificity, balanced accuracy, MCC and the
paired McNemar test all use these outcomes; ``case.out_of_taxonomy_alarms``
counts the negative cases that are false alarms only through out-of-taxonomy
reports.

Agent tier. Among expected ``agent`` entities, agent recall is the share found
by a report labeled ``agent``. The agent false-alarm rate is the share of
expected ``llm`` entities and decoys that a report labeled ``agent`` hit, on
``ok`` rows only. An error reports nothing and an incomplete run did not look
at everything, so neither may lower the rate: an error row is left out, and an
incomplete row adds only the entities it did call agents to the universe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, get_args

from tools.discovery_benchmark.taxonomy import is_fact
from tools.shadowbench.cases.adapters.registry import load_adapters
from tools.shadowbench.cases.contract import SURFACES, Status
from tools.shadowbench.cases.corpus import Case, Corpus, corpus_digest, load_corpus

STATUSES: frozenset[str] = frozenset(get_args(Status))
"""The row statuses the runner writes; any other status is refused, never skipped."""

ROW_FIELDS: tuple[str, ...] = ("surface", "modality", "family", "label", "difficulty")
"""Case fields the runner copies into every row; a row that disagrees was recorded on another case."""

Withheld = dict[tuple[str, str], tuple[str, ...]]
"""Per (surface, modality), the key prefixes of the decoys an adapter never passes to its tool."""

Support = frozenset[tuple[str, str]]
"""The (surface, modality) pairs an adapter declares it runs."""


class ResultsError(ValueError):
    """Stored results that cannot be scored against this corpus without misreporting."""


def withheld_decoys(
    tools: Iterable[str], registry: tuple[Mapping[str, Any], Mapping[str, str]] | None = None
) -> tuple[dict[str, Withheld], list[str]]:
    """Each tool's declared ``withheld_decoys``, and a problem for each adapter module that does not load.

    ``registry`` is what ``load_adapters`` returned, loaded here when not given.
    """
    adapters, unloaded = registry if registry is not None else load_adapters()
    out: dict[str, Withheld] = {}
    for tool in tools:
        declared = getattr(adapters.get(tool), "withheld_decoys", None) or {}
        if not isinstance(declared, Mapping):
            raise ResultsError(
                f"adapter {tool}: withheld_decoys must map (surface, modality) to key prefixes"
            )
        entry: Withheld = {}
        for where, prefixes in declared.items():
            if (
                not isinstance(where, tuple)
                or len(where) != 2
                or not all(isinstance(part, str) for part in where)
                or not isinstance(prefixes, tuple | list | frozenset)
                or not prefixes
                or not all(isinstance(p, str) and p for p in prefixes)
            ):
                raise ResultsError(f"adapter {tool}: malformed withheld_decoys entry {where!r}: {prefixes!r}")
            entry[(where[0], where[1])] = tuple(sorted(prefixes))
        out[tool] = entry
    problems = [
        f"adapter module {module} does not load ({why}), so the decoys it withholds from its tool are unknown"
        for module, why in sorted(unloaded.items())
    ]
    return out, problems


def declared_support(adapter: object) -> Support | None:
    """The (surface, modality) pairs ``adapter`` declares in ``surfaces``.

    None without an adapter or without a well-formed declaration: then nothing is unsupported on its word.
    """
    surfaces = getattr(adapter, "surfaces", None)
    if not isinstance(surfaces, Mapping):
        return None
    pairs: set[tuple[str, str]] = set()
    for surface, modalities in surfaces.items():
        if not isinstance(surface, str) or not isinstance(modalities, frozenset | set | tuple | list):
            return None
        if not all(isinstance(modality, str) for modality in modalities):
            return None
        pairs.update((surface, modality) for modality in modalities)
    return frozenset(pairs)


def missing_row_status(
    pairs_run: Mapping[tuple[str, str], bool], support: Support | None, case: Case
) -> Status:
    """How a case the tool has no row for is scored: ``unsupported`` where the tool does not run.

    The runner decides support per (surface, modality) and writes an ``unsupported`` row for every
    case it does not run, so the tool's rows on the case's pair (``pairs_run``: whether they are
    ``ok`` or ``error`` rather than ``unsupported``) say what this one would have been. With none
    there, the adapter's declaration decides. Anything else is an ``error``.
    """
    where = (case.surface, case.modality)
    if where in pairs_run:
        return "error" if pairs_run[where] else "unsupported"
    return "unsupported" if support is not None and where not in support else "error"


def wilson(k: int, n: int) -> tuple[float | None, float | None, float | None]:
    if n == 0:
        return None, None, None
    z = 1.959964
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2.0**n
    return min(1.0, 2 * tail)


def _key_match(reported: str, truth: str) -> bool:
    """Whether ``reported`` names ``truth``: the same key, or an artifact path inside the truth directory."""
    if reported == truth:
        return True
    if reported.startswith("artifact:") and truth.startswith("artifact:"):
        inner, outer = reported[9:].rstrip("/"), truth[9:].rstrip("/")
        return inner.startswith(outer + "/")
    return False


def _matches(reported: str, keys: list[str]) -> list[str]:
    return [k for k in keys if _key_match(reported, k)]


class CaseScore:
    """Entity-level outcome of one (tool, case); ``row`` is ``None`` when the tool has no row for it.

    ``withheld`` holds the key prefixes of the decoys the tool's adapter never passed to it on this
    case's surface and modality. ``missing_status`` is how a missing row is scored: an ``error``,
    or ``unsupported`` where the tool does not run (``missing_row_status``).
    """

    def __init__(
        self,
        case: Case,
        row: dict[str, Any] | None,
        withheld: tuple[str, ...] = (),
        missing_status: Status = "error",
    ) -> None:
        self.case = case
        self.missing = row is None
        if row is None:
            row = {"status": missing_status, "entities": [], "incomplete": False, "seconds": 0.0}
        self.status = str(row["status"])
        self.incomplete = bool(row.get("incomplete"))
        # only a complete ok run can vouch for what it did not report
        self.complete = self.status == "ok" and not self.incomplete
        self.seconds = float(row.get("seconds") or 0.0)
        expected = {e.key: e for e in case.expected}
        tolerated = set(case.tolerated)
        self.tp: set[str] = set()
        self.tp_agent: set[str] = set()
        self.fp_keys: set[str] = set()
        self.decoy_hits: set[str] = set()
        self.agent_false_alarms: set[str] = set()
        self.out_of_taxonomy: set[str] = set()
        self.dropped_out_of_taxonomy = 0
        self.extra = 0
        # decoys the tool was never shown; one it reports anyway is a hit, and leaves this set below
        self.withheld: set[str] = {d for d in case.decoys if withheld and d.startswith(withheld)}
        if self.status != "ok":
            return
        # code hits the adapter could not map to a fact and dropped, counted in the row
        self.dropped_out_of_taxonomy = int(row.get("out_of_taxonomy") or 0)
        seen: set[str] = set()
        for ent in row["entities"]:
            key = str(ent["key"])
            label = str(ent["label"])
            if key in seen:
                continue
            seen.add(key)
            if case.surface == "code" and not is_fact(key):
                self.out_of_taxonomy.add(key)
                continue
            if key in tolerated:
                continue
            hit_expected = _matches(key, list(expected))
            hit_decoy = _matches(key, case.decoys)
            if hit_expected:
                for k in hit_expected:
                    self.tp.add(k)
                    if label == "agent":
                        if expected[k].label == "agent":
                            self.tp_agent.add(k)
                        else:
                            self.agent_false_alarms.add(k)
            elif hit_decoy:
                self.decoy_hits.update(hit_decoy)
                if label == "agent":
                    self.agent_false_alarms.update(hit_decoy)
            else:
                self.fp_keys.add(key)
                self.extra += 1
        self.withheld -= self.decoy_hits

    @property
    def fn(self) -> int:
        return len(self.case.expected) - len(self.tp)

    @property
    def fp(self) -> int:
        return len(self.decoy_hits) + self.extra

    @property
    def out_of_taxonomy_reports(self) -> int:
        """Code reports outside the fact taxonomy: keys passed on plus hits the adapter dropped."""
        return len(self.out_of_taxonomy) + self.dropped_out_of_taxonomy

    @property
    def decoy_universe(self) -> int:
        """The decoys this row is scored on: the case's, less those withheld from the tool."""
        return len(self.case.decoys) - len(self.withheld)

    @property
    def tn(self) -> int:
        """Decoys left alone; an error or an incomplete run earns none, and a withheld decoy is none."""
        return self.decoy_universe - len(self.decoy_hits) if self.complete else 0

    @property
    def blind(self) -> bool:
        """A complete, clean run on a negative case whose every decoy was withheld from the tool.

        The tool was shown nothing it could reject, so the case is no correct negative for it.
        """
        return (
            self.complete
            and not self.case.positive
            and bool(self.case.decoys)
            and self.decoy_universe == 0
            and self.fp == 0
            and not self.out_of_taxonomy_reports
        )

    @property
    def agent_false_alarm_universe(self) -> int:
        """Entities this row could have wrongly called agents; an incomplete run adds only those it did."""
        if not self.complete:
            return len(self.agent_false_alarms) if self.status == "ok" else 0
        return sum(1 for e in self.case.expected if e.label == "llm") + self.decoy_universe

    @property
    def correct(self) -> bool:
        """Case-level outcome: a positive case needs a true positive, a negative one no alarm at all.

        An ``error`` (or missing) row is never correct, whatever the case label, and an incomplete
        run is never a correct negative. On a negative case an out-of-taxonomy report is an alarm
        like a false positive, though at entity level it is neither.
        """
        if self.status != "ok":
            return False
        if self.case.positive:
            return bool(self.tp)
        return self.fp == 0 and not self.out_of_taxonomy_reports and not self.incomplete


def _aggregate(scores: list[CaseScore], reps: int = 2000, seed: int = 7) -> dict[str, Any]:
    ok = [s for s in scores if s.status == "ok"]
    scored = [s for s in scores if s.status in ("ok", "error")]
    tp = sum(len(s.tp) for s in ok)
    fn = sum(s.fn for s in scored)
    fp = sum(s.fp for s in ok)
    tn = sum(s.tn for s in ok)
    decoys = sum(s.decoy_universe for s in scored)
    exp_agents = sum(1 for s in scored for e in s.case.expected if e.label == "agent")
    tp_agent = sum(len(s.tp_agent) for s in ok)
    fa_universe = sum(s.agent_false_alarm_universe for s in ok)
    fa = sum(len(s.agent_false_alarms) for s in ok)
    precision = wilson(tp, tp + fp)
    recall = wilson(tp, tp + fn)
    # the decoys of an error or incomplete row are in the denominator but never true negatives
    specificity = wilson(tn, decoys)
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None
    # bootstrap F1 over cases
    rng = random.Random(seed)
    boots: list[float] = []
    if scored and f1 is not None:
        for _ in range(reps):
            sample = [scored[rng.randrange(len(scored))] for _ in scored]
            btp = sum(len(s.tp) for s in sample)
            bfp = sum(s.fp for s in sample)
            bfn = sum(s.fn for s in sample)
            if 2 * btp + bfp + bfn:
                boots.append(2 * btp / (2 * btp + bfp + bfn))
        boots.sort()
    # case level: an error is a missed positive, an error or incomplete negative a false alarm, and
    # a negative case the tool was shown no decoy of is no outcome at all
    pos = [s for s in scored if s.case.positive]
    neg = [s for s in scored if not s.case.positive and not s.blind]
    ctp = sum(1 for s in pos if s.correct)
    cfn = len(pos) - ctp
    ctn = sum(1 for s in neg if s.correct)
    cfp = len(neg) - ctn
    bal = None
    mcc = None
    if pos and neg:
        bal = (ctp / len(pos) + ctn / len(neg)) / 2
        denom = math.sqrt((ctp + cfp) * (ctp + cfn) * (ctn + cfp) * (ctn + cfn))
        mcc = (ctp * ctn - cfp * cfn) / denom if denom else None
    secs = [s.seconds for s in ok]
    return {
        "cases": len(scores),
        "scored": len(scored),
        "errors": sum(1 for s in scores if s.status == "error"),
        "missing": sum(1 for s in scores if s.missing),
        "incomplete": sum(1 for s in ok if s.incomplete),
        "expected": tp + fn,
        "decoys": decoys,
        "decoys_withheld": sum(len(s.withheld) for s in scored),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "out_of_taxonomy": sum(s.out_of_taxonomy_reports for s in ok),
        "precision": precision[0],
        "precision_ci": precision[1:],
        "recall": recall[0],
        "recall_ci": recall[1:],
        "specificity": specificity[0],
        "specificity_ci": specificity[1:],
        "f1": f1,
        "f1_ci": (boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots)) - 1])
        if len(boots) > 40
        else None,
        "agent_expected": exp_agents,
        "agent_tp": tp_agent,
        "agent_recall": tp_agent / exp_agents if exp_agents else None,
        "agent_false_alarms": fa,
        "agent_false_alarm_universe": fa_universe,
        "agent_false_alarm_rate": fa / fa_universe if fa_universe else None,
        "case": {
            "positives": len(pos),
            "negatives": len(neg),
            "negatives_withheld": sum(1 for s in scored if s.blind),
            "out_of_taxonomy_alarms": sum(
                1 for s in neg if s.complete and s.fp == 0 and s.out_of_taxonomy_reports
            ),
            "tp": ctp,
            "fn": cfn,
            "fp": cfp,
            "tn": ctn,
            "recall": ctp / len(pos) if pos else None,
            "specificity": ctn / len(neg) if neg else None,
            "balanced_accuracy": bal,
            "mcc": mcc,
        },
        "seconds_median": float(statistics.median(secs)) if secs else None,
        "seconds_p90": sorted(secs)[int(0.9 * (len(secs) - 1))] if secs else None,
        "seconds_max": max(secs) if secs else None,
    }


def _check_row(row: Any, where: str, cases: dict[str, Case], tool: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ResultsError(f"{where}: a row must be a JSON object")
    cid = row.get("case")
    if not isinstance(cid, str) or cid not in cases:
        raise ResultsError(f"{where}: case {cid!r} is not in the corpus")
    if row.get("tool") != tool:
        raise ResultsError(f"{where}: {cid}: row tool {row.get('tool')!r} is not the file's tool {tool!r}")
    status = row.get("status")
    if status not in STATUSES:
        raise ResultsError(f"{where}: {cid}: unknown status {status!r} (expected one of {sorted(STATUSES)})")
    case = cases[cid]
    # case ids are positional (runtime-live-003), so these fields are what ties a row to its case
    for field in ROW_FIELDS:
        truth = getattr(case, field)
        if row.get(field) != truth:
            raise ResultsError(
                f"{where}: {cid}: row {field} {row.get(field)!r} disagrees with the corpus ({truth!r})"
            )
    if not isinstance(row.get("incomplete", False), bool):
        raise ResultsError(f"{where}: {cid}: incomplete must be true or false")
    if "out_of_taxonomy" in row:
        dropped = row["out_of_taxonomy"]
        if not isinstance(dropped, int) or isinstance(dropped, bool) or dropped < 0:
            raise ResultsError(f"{where}: {cid}: out_of_taxonomy must be a count, not {dropped!r}")
        if case.surface != "code":
            raise ResultsError(f"{where}: {cid}: out_of_taxonomy is for code rows only")
    entities = row.get("entities")
    if not isinstance(entities, list):
        raise ResultsError(f"{where}: {cid}: entities must be a list")
    if status == "ok":
        for ent in entities:
            if not isinstance(ent, dict) or not isinstance(ent.get("key"), str) or not ent["key"]:
                raise ResultsError(f"{where}: {cid}: an entity without a key")
            if not isinstance(ent.get("label"), str):
                raise ResultsError(f"{where}: {cid}: entity {ent['key']!r} has no label")
    return row


def load_rows(results: Path, corpus: Corpus) -> dict[str, dict[str, dict[str, Any]]]:
    """Read every ``<tool>.jsonl`` under ``results``; refuse rows that cannot be scored against ``corpus``."""
    cases = {c.case_id: c for c in corpus.cases}
    rows: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(results.glob("*.jsonl")):
        tool = path.stem
        rows[tool] = {}
        with path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                where = f"{path.name}:{n}"
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ResultsError(f"{where}: unreadable row: {exc}") from exc
                row = _check_row(data, where, cases, tool)
                if row["case"] in rows[tool]:
                    raise ResultsError(f"{where}: second row for case {row['case']}")
                rows[tool][row["case"]] = row
        # the runner decides support per (surface, modality); a mix means an edited or corrupt file
        support: dict[tuple[str, str], set[bool]] = {}
        for row in rows[tool].values():
            support.setdefault((row["surface"], row["modality"]), set()).add(row["status"] == "unsupported")
        for (surface, modality), kinds in sorted(support.items()):
            if len(kinds) > 1:
                raise ResultsError(
                    f"{path.name}: {surface}/{modality} has unsupported rows alongside ok or error rows"
                )
    return rows


def _provenance(
    rows: dict[str, dict[str, dict[str, Any]]], tool_runs: dict[str, Any], results: Path
) -> tuple[set[str], list[str], list[str]]:
    """The tools the manifest says ran, every way the results files disagree with it, and the
    tools whose results file it records no digest of."""
    problems: list[str] = []
    unbound: list[str] = []
    ran: set[str] = set()
    for name, run in tool_runs.items():
        if not isinstance(run, dict):
            raise ResultsError(f"manifest: tools.{name} must be a JSON object")
        if not run.get("skipped"):
            ran.add(name)
    for tool in sorted(set(rows) | ran):
        run = tool_runs.get(tool)
        if run is None:
            problems.append(f"{tool}.jsonl: the manifest does not list {tool}, so no run vouches for it")
            continue
        if run.get("skipped"):
            problems.append(f"{tool}.jsonl: the manifest records {tool} as not run ({run['skipped']})")
            continue
        recorded = run.get("statuses")
        found = dict(Counter(str(r["status"]) for r in rows.get(tool, {}).values()))
        if not isinstance(recorded, dict):
            problems.append(f"{tool}: the manifest records no row statuses to check {tool}.jsonl against")
        elif {k: v for k, v in recorded.items() if v} != found:
            problems.append(
                f"{tool}.jsonl: row statuses {dict(sorted(found.items()))} differ from the "
                f"{dict(sorted(recorded.items()))} the manifest recorded"
            )
        digest = run.get("rows_sha256")
        path = results / f"{tool}.jsonl"
        if digest is None:
            unbound.append(tool)
        elif not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"{tool}.jsonl: its SHA-256 is not the one the manifest recorded ({digest})")
    return ran, problems, unbound


def score(
    corpus: Corpus,
    results: Path,
    reference: str = "shadowscan",
    *,
    corpus_sha256: str,
    force: bool = False,
) -> dict[str, Any]:
    """Metrics for every tool under ``results``; ``corpus_sha256`` is the digest of the corpus file scored."""
    manifest_path = results / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    except json.JSONDecodeError as exc:
        raise ResultsError(f"{manifest_path}: unreadable manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ResultsError(f"{manifest_path}: the manifest must be a JSON object")
    forced: list[str] = []

    def refuse_unless_forced(problem: str) -> None:
        if not force:
            raise ResultsError(f"{problem} (--force overrides)")
        forced.append(problem)

    recorded = manifest.get("corpus_sha256")
    if recorded != corpus_sha256:
        refuse_unless_forced(
            f"{results}: results were recorded against corpus {recorded or '(not recorded)'}, "
            f"not this corpus ({corpus_sha256}); case ids are positional, so refusing to score"
        )
    for case in corpus.cases:
        if case.surface == "code":
            for key in [e.key for e in case.expected] + case.tolerated + case.decoys:
                if not is_fact(key):
                    raise ResultsError(f"{case.case_id}: code truth key {key!r} is not a taxonomy fact")
    rows = load_rows(results, corpus)
    tool_runs = manifest.get("tools", {})
    if not isinstance(tool_runs, dict):
        raise ResultsError(f"{manifest_path}: tools must be a JSON object")
    ran, problems, unbound = _provenance(rows, tool_runs, results)
    registry = load_adapters()
    withheld, unloaded = withheld_decoys(sorted(set(rows) | ran), registry)
    for problem in problems + unloaded:
        refuse_unless_forced(problem)
    out: dict[str, Any] = {
        "corpus_sha256": recorded,
        "corpus_sha256_now": corpus_sha256,
        "corpus_mismatch_forced": recorded != corpus_sha256,
        "forced": forced,
        "rows_unbound": unbound,
        "generator_digest": corpus.generator_digest,
        "manifest": {k: v for k, v in manifest.items() if k != "tools"},
        "tool_runs": tool_runs,
        "surfaces": {},
        "tools": {},
    }
    for surface in SURFACES:
        cs = [c for c in corpus.cases if c.surface == surface]
        out["surfaces"][surface] = {
            "cases": len(cs),
            "positives": sum(1 for c in cs if c.positive),
            "expected": sum(len(c.expected) for c in cs),
            "decoys": sum(len(c.decoys) for c in cs),
            "modalities": sorted({c.modality for c in cs}),
        }
    all_scores: dict[str, dict[str, CaseScore]] = {}
    # a forced score of a tool the manifest says ran but whose rows are gone scores as all missing:
    # errors, except on the pairs its adapter does not declare
    for tool in sorted(set(rows) | ran):
        by_case = rows.get(tool, {})
        # load_rows refuses unsupported rows beside ok or error rows on one pair
        pairs_run = {(r["surface"], r["modality"]): r["status"] != "unsupported" for r in by_case.values()}
        support = declared_support(registry[0].get(tool))
        scores = {
            c.case_id: CaseScore(
                c,
                by_case.get(c.case_id),
                withheld[tool].get((c.surface, c.modality), ()),
                missing_row_status(pairs_run, support, c),
            )
            for c in corpus.cases
        }
        all_scores[tool] = scores
        supported = sorted({s.case.surface for s in scores.values() if s.status != "unsupported"})
        per_surface: dict[str, Any] = {}
        for surface in SURFACES:
            sub = [s for s in scores.values() if s.case.surface == surface and s.status != "unsupported"]
            if not sub:
                continue
            entry = _aggregate(sub)
            entry["modalities"] = {}
            for modality in sorted({s.case.modality for s in sub}):
                entry["modalities"][modality] = _aggregate([s for s in sub if s.case.modality == modality])
            per_surface[surface] = entry
        in_scope = _aggregate([s for s in scores.values() if s.status != "unsupported"])
        total_expected = sum(len(c.expected) for c in corpus.cases)
        estate_tp = sum(len(s.tp) for s in scores.values() if s.status == "ok")
        out["tools"][tool] = {
            "version": (tool_runs.get(tool) or {}).get("version"),
            "surfaces_supported": supported,
            "coverage": f"{len(supported)}/{len([s for s in SURFACES if out['surfaces'][s]['cases']])}",
            "withheld_decoys": {f"{s}/{m}": list(p) for (s, m), p in sorted(withheld[tool].items())},
            "in_scope": in_scope,
            "estate": {
                "expected": total_expected,
                "tp": estate_tp,
                "recall": estate_tp / total_expected if total_expected else None,
            },
            "by_surface": per_surface,
        }
    # paired case-level comparison with the reference tool on cases both support
    ref = all_scores.get(reference)
    if ref:
        for tool, scores in all_scores.items():
            if tool == reference:
                continue
            b = c = shared = 0
            for cid, s in scores.items():
                r = ref[cid]
                if s.status == "unsupported" or r.status == "unsupported" or s.blind or r.blind:
                    continue
                shared += 1
                if s.correct and not r.correct:
                    b += 1
                elif r.correct and not s.correct:
                    c += 1
            out["tools"][tool]["vs_reference"] = {
                "reference": reference,
                "shared": shared,
                "tool_only_correct": b,
                "reference_only_correct": c,
                "mcnemar_p": mcnemar_exact(b, c) if shared else None,
            }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--reference", default="shadowscan")
    ap.add_argument(
        "--force",
        action="store_true",
        help="score results the manifest does not vouch for: another corpus digest, a results file for "
        "a tool it does not record as run, row statuses that differ from its counts, or a results file "
        "whose SHA-256 differs from the one it recorded (recorded in the metrics)",
    )
    args = ap.parse_args(argv)
    corpus = load_corpus(args.corpus)
    try:
        metrics = score(
            corpus, args.results, args.reference, corpus_sha256=corpus_digest(args.corpus), force=args.force
        )
    except ResultsError as exc:
        print(f"refusing to score: {exc}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    for problem in metrics["forced"]:
        print(f"warning: scored with --force despite: {problem}", file=sys.stderr)
    for tool, t in metrics["tools"].items():
        i = t["in_scope"]
        if i["missing"]:
            print(f"warning: {tool}: {i['missing']} cases have no row and count as errors", file=sys.stderr)
        print(
            f"{tool}: coverage {t['coverage']}, in-scope P/R/F1 {i['precision']}/{i['recall']}/{i['f1']}, estate recall {t['estate']['recall']}"  # noqa: E501
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
