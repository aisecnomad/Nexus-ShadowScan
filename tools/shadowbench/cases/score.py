"""Score stored runs against the corpus: entity-level and case-level metrics per tool and surface.

``python -m tools.shadowbench.cases score --corpus corpus.json --results results/ --out metrics.json``
(``--force`` scores results recorded against a different corpus file)

Inputs. Every tool is scored on every case of the corpus. The results
manifest must name the SHA-256 of the corpus file being scored: case ids are
positional, so results recorded against another corpus (another seed, an
edited rubric) would be scored against the wrong truth. A mismatch, or a
manifest without the digest, is refused unless ``--force`` is given, and a
forced score records the mismatch. A row with a status other than ``ok``,
``error`` or ``unsupported``, a second row for the same case, a row for a case
the corpus does not have, or a row whose surface or modality disagrees with
its case is refused. A case with no row counts as an ``error`` and is also
reported as missing.

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
neither a true nor a false positive, and counted per tool. The rule is the
same for every tool, whether its adapter drops such hits or passes them on.

Rules. An ``error`` row (crash, timeout, unreadable output, missing row) is
never a correct outcome: every expected entity counts as missed, its decoys
count against specificity (they are not true negatives, and are not reported
false positives either), a positive case counts as missed and a negative case
as a false alarm. An ``unsupported`` row is excluded from in-scope metrics and
counted as missed in estate recall. An incomplete run (a tool that says it did
not read everything) is scored on what it reported and counted separately.

Case level. A positive case is found when the tool reports at least one
expected entity; a negative case is a false alarm when the tool reports at
least one false positive. Case recall, specificity, balanced accuracy, MCC and
the paired McNemar test all use these outcomes.

Agent tier. Among expected ``agent`` entities, agent recall is the share found
by a report labeled ``agent``. The agent false-alarm rate is the share of
expected ``llm`` entities and decoys that a report labeled ``agent`` hit, on
``ok`` rows only (an error reports nothing, so it must not lower the rate).
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any, get_args

from tools.discovery_benchmark.taxonomy import is_fact
from tools.shadowbench.cases.contract import SURFACES, Status
from tools.shadowbench.cases.corpus import Case, Corpus, corpus_digest, load_corpus

STATUSES: frozenset[str] = frozenset(get_args(Status))
"""The row statuses the runner writes; any other status is refused, never skipped."""


class ResultsError(ValueError):
    """Stored results that cannot be scored against this corpus without misreporting."""


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
    """Entity-level outcome of one (tool, case); ``row`` is ``None`` when the tool has no row for it."""

    def __init__(self, case: Case, row: dict[str, Any] | None) -> None:
        self.case = case
        self.missing = row is None
        if row is None:
            row = {"status": "error", "entities": [], "incomplete": False, "seconds": 0.0}
        self.status = str(row["status"])
        self.incomplete = bool(row.get("incomplete"))
        self.seconds = float(row.get("seconds") or 0.0)
        expected = {e.key: e for e in case.expected}
        tolerated = set(case.tolerated)
        self.tp: set[str] = set()
        self.tp_agent: set[str] = set()
        self.fp_keys: set[str] = set()
        self.decoy_hits: set[str] = set()
        self.agent_false_alarms: set[str] = set()
        self.out_of_taxonomy: set[str] = set()
        self.extra = 0
        if self.status != "ok":
            return
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

    @property
    def fn(self) -> int:
        return len(self.case.expected) - len(self.tp)

    @property
    def fp(self) -> int:
        return len(self.decoy_hits) + self.extra

    @property
    def tn(self) -> int:
        return len(self.case.decoys) - len(self.decoy_hits) if self.status == "ok" else 0

    @property
    def correct(self) -> bool:
        """Case-level outcome: a positive case needs a true positive, a negative one no false positive.

        An ``error`` (or missing) row is never correct, whatever the case label.
        """
        if self.status != "ok":
            return False
        return bool(self.tp) if self.case.positive else self.fp == 0


def _aggregate(scores: list[CaseScore], reps: int = 2000, seed: int = 7) -> dict[str, Any]:
    ok = [s for s in scores if s.status == "ok"]
    scored = [s for s in scores if s.status in ("ok", "error")]
    tp = sum(len(s.tp) for s in ok)
    fn = sum(s.fn for s in scored)
    fp = sum(s.fp for s in ok)
    tn = sum(s.tn for s in ok)
    decoys = sum(len(s.case.decoys) for s in scored)
    exp_agents = sum(1 for s in scored for e in s.case.expected if e.label == "agent")
    tp_agent = sum(len(s.tp_agent) for s in ok)
    fa_universe = sum(sum(1 for e in s.case.expected if e.label == "llm") + len(s.case.decoys) for s in ok)
    fa = sum(len(s.agent_false_alarms) for s in ok)
    precision = wilson(tp, tp + fp)
    recall = wilson(tp, tp + fn)
    # the decoys of an error row are in the denominator but never true negatives
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
    # case level: an error is a missed positive or a false alarm on a negative
    pos = [s for s in scored if s.case.positive]
    neg = [s for s in scored if not s.case.positive]
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
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "out_of_taxonomy": sum(len(s.out_of_taxonomy) for s in ok),
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


def _check_row(row: Any, where: str, cases: dict[str, Case]) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ResultsError(f"{where}: a row must be a JSON object")
    cid = row.get("case")
    if not isinstance(cid, str) or cid not in cases:
        raise ResultsError(f"{where}: case {cid!r} is not in the corpus")
    status = row.get("status")
    if status not in STATUSES:
        raise ResultsError(f"{where}: {cid}: unknown status {status!r} (expected one of {sorted(STATUSES)})")
    case = cases[cid]
    for field in ("surface", "modality"):
        truth = getattr(case, field)
        if field in row and row[field] != truth:
            raise ResultsError(
                f"{where}: {cid}: row {field} {row[field]!r} disagrees with the corpus ({truth!r})"
            )
    if not isinstance(row.get("incomplete", False), bool):
        raise ResultsError(f"{where}: {cid}: incomplete must be true or false")
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
                row = _check_row(data, where, cases)
                if row["case"] in rows[tool]:
                    raise ResultsError(f"{where}: second row for case {row['case']}")
                rows[tool][row["case"]] = row
    return rows


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
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    if not isinstance(manifest, dict):
        raise ResultsError(f"{manifest_path}: the manifest must be a JSON object")
    recorded = manifest.get("corpus_sha256")
    if recorded != corpus_sha256 and not force:
        raise ResultsError(
            f"{results}: results were recorded against corpus {recorded or '(not recorded)'}, "
            f"not this corpus ({corpus_sha256}); case ids are positional, so refusing to score "
            "(--force overrides)"
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
    ran = {name for name, run in tool_runs.items() if isinstance(run, dict) and not run.get("skipped")}
    out: dict[str, Any] = {
        "corpus_sha256": recorded,
        "corpus_sha256_now": corpus_sha256,
        "corpus_mismatch_forced": recorded != corpus_sha256,
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
    # a tool the manifest says ran but whose rows are gone scores as all missing, never as absent
    for tool in sorted(set(rows) | ran):
        by_case = rows.get(tool, {})
        scores = {c.case_id: CaseScore(c, by_case.get(c.case_id)) for c in corpus.cases}
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
                if s.status == "unsupported" or r.status == "unsupported":
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
        help="score results whose manifest names a different corpus digest (recorded in the metrics)",
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
    if metrics["corpus_mismatch_forced"]:
        print(
            "warning: scored with --force against a corpus the results were not recorded on", file=sys.stderr
        )
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
