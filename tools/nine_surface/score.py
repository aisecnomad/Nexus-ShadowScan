"""Score stored runs against the corpus: entity-level and case-level metrics per tool and surface.

``python -m tools.nine_surface score --corpus corpus.json --results results/ --out metrics.json``

Matching. A reported key matches an expected or decoy key when they are
equal, or, for ``artifact:`` keys, when one path is a parent directory of the
other (a tool that names the client directory, or a file inside the expected
directory, has found the artifact). Reported keys are de-duplicated. A reported
key that matches nothing expected or tolerated is a false positive; when it
matches a decoy it also counts against specificity.

Rules. An ``error`` row (crash, timeout, unreadable output) counts every
expected entity as missed and reports no decoys; it is never a clean negative.
An ``unsupported`` row is excluded from in-scope metrics and counted as missed
in estate recall. An incomplete run (a tool that says it did not read
everything) is scored on what it reported and counted separately.

Agent tier. Among expected ``agent`` entities, agent recall is the share found
by a report labeled ``agent``. The agent false-alarm rate is the share of
expected ``llm`` entities and decoys that a report labeled ``agent`` hit.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any

from tools.nine_surface.contract import SURFACES
from tools.nine_surface.corpus import Case, Corpus, corpus_digest, load_corpus


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


def _artifact_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if a.startswith("artifact:") and b.startswith("artifact:"):
        pa, pb = a[9:].rstrip("/"), b[9:].rstrip("/")
        return pa.startswith(pb + "/") or pb.startswith(pa + "/")
    return False


def _matches(reported: str, keys: list[str]) -> list[str]:
    return [k for k in keys if _artifact_match(reported, k)]


class CaseScore:
    """Entity-level outcome of one (tool, case)."""

    def __init__(self, case: Case, row: dict[str, Any]) -> None:
        self.case = case
        self.status = str(row.get("status"))
        self.incomplete = bool(row.get("incomplete"))
        self.seconds = float(row.get("seconds") or 0.0)
        expected = {e.key: e for e in case.expected}
        self.tp: set[str] = set()
        self.tp_agent: set[str] = set()
        self.fp_keys: set[str] = set()
        self.decoy_hits: set[str] = set()
        self.agent_false_alarms: set[str] = set()
        self.extra = 0
        if self.status != "ok":
            return
        seen: set[str] = set()
        for ent in row.get("entities", []):
            key = str(ent.get("key"))
            label = str(ent.get("label"))
            if key in seen:
                continue
            seen.add(key)
            hit_expected = _matches(key, list(expected))
            hit_decoy = _matches(key, case.decoys)
            hit_tolerated = _matches(key, case.tolerated)
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
            elif not hit_tolerated:
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
    def detected(self) -> bool:
        return bool(self.tp or self.fp)


def _aggregate(scores: list[CaseScore], reps: int = 2000, seed: int = 7) -> dict[str, Any]:
    ok = [s for s in scores if s.status == "ok"]
    tp = sum(len(s.tp) for s in ok)
    fn = sum(s.fn for s in scores if s.status in ("ok", "error"))
    fp = sum(s.fp for s in ok)
    tn = sum(s.tn for s in ok)
    exp_agents = sum(
        1 for s in scores if s.status in ("ok", "error") for e in s.case.expected if e.label == "agent"
    )
    tp_agent = sum(len(s.tp_agent) for s in ok)
    fa_universe = sum(sum(1 for e in s.case.expected if e.label == "llm") + len(s.case.decoys) for s in ok)
    fa = sum(len(s.agent_false_alarms) for s in ok)
    precision = wilson(tp, tp + fp)
    recall = wilson(tp, tp + fn)
    specificity = wilson(tn, tn + sum(len(s.decoy_hits) for s in ok))
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None
    # bootstrap F1 over cases
    rng = random.Random(seed)
    scored = [s for s in scores if s.status in ("ok", "error")]
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
    # case level
    pos = [s for s in scored if s.case.positive]
    neg = [s for s in scored if not s.case.positive]
    ctp = sum(1 for s in pos if s.detected)
    cfn = len(pos) - ctp
    cfp = sum(1 for s in neg if s.detected)
    ctn = len(neg) - cfp
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
        "incomplete": sum(1 for s in ok if s.incomplete),
        "expected": tp + fn,
        "decoys": sum(len(s.case.decoys) for s in ok),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
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


def load_rows(results: Path) -> dict[str, dict[str, dict[str, Any]]]:
    rows: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(results.glob("*.jsonl")):
        tool = path.stem
        rows[tool] = {}
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    rows[tool][str(row["case"])] = row
    return rows


def score(corpus: Corpus, results: Path, reference: str = "shadowscan") -> dict[str, Any]:
    rows = load_rows(results)
    manifest_path = results / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    cases = {c.case_id: c for c in corpus.cases}
    out: dict[str, Any] = {
        "corpus_sha256": manifest.get("corpus_sha256"),
        "generator_digest": corpus.generator_digest,
        "manifest": {k: v for k, v in manifest.items() if k != "tools"},
        "tool_runs": manifest.get("tools", {}),
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
    for tool, by_case in rows.items():
        scores = {cid: CaseScore(cases[cid], row) for cid, row in by_case.items() if cid in cases}
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
        total_expected = sum(len(c.expected) for c in corpus.cases if c.case_id in scores)
        estate_tp = sum(len(s.tp) for s in scores.values() if s.status == "ok")
        out["tools"][tool] = {
            "version": (manifest.get("tools", {}).get(tool) or {}).get("version"),
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
            b = c = 0
            for cid, s in scores.items():
                r = ref.get(cid)
                if r is None or s.status == "unsupported" or r.status == "unsupported":
                    continue
                correct_tool = s.detected == s.case.positive and s.status == "ok"
                correct_ref = r.detected == r.case.positive and r.status == "ok"
                if correct_tool and not correct_ref:
                    b += 1
                elif correct_ref and not correct_tool:
                    c += 1
            out["tools"][tool]["vs_reference"] = {
                "reference": reference,
                "tool_only_correct": b,
                "reference_only_correct": c,
                "mcnemar_p": mcnemar_exact(b, c),
            }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--reference", default="shadowscan")
    args = ap.parse_args(argv)
    corpus = load_corpus(args.corpus)
    metrics = score(corpus, args.results, args.reference)
    metrics["corpus_sha256_now"] = corpus_digest(args.corpus)
    args.out.write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    for tool, t in metrics["tools"].items():
        i = t["in_scope"]
        print(
            f"{tool}: coverage {t['coverage']}, in-scope P/R/F1 {i['precision']}/{i['recall']}/{i['f1']}, estate recall {t['estate']['recall']}"  # noqa: E501
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
