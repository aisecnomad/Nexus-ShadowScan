# Review logs

Internal, AI-assisted hardening and review logs from September and October
2026, kept for history. They are not part of the published documentation and are not
independent review; see [governance](../../docs/governance.md).

Each record was written by the maintainer with an AI assistant while changing
the code it describes, and says so in its first lines. None is a second-person
or third-party audit, and none is live tenant acceptance. Files here are
retained as written: the pre-commit whitespace hooks skip `archive/`.

| Record | Date | What it covers |
|---|---|---|
| [`production-review-2026-09-24.md`](production-review-2026-09-24.md) | 2026-09-24 | Production hardening log |
| [`production-review-2026-09-24-round2.md`](production-review-2026-09-24-round2.md) | 2026-09-24 | Second production hardening round |
| [`security-review-2026-09-24.md`](security-review-2026-09-24.md) | 2026-09-24 | Software and security hardening log |
| [`followup-review-2026-09-24.md`](followup-review-2026-09-24.md) | 2026-09-24 | Follow-up security and reliability log |
| [`consolidated-review-2026-09-24.md`](consolidated-review-2026-09-24.md) | 2026-09-24 | Consolidated hardening log across the then-open hardening pull requests (#26, #29, #30, #31) |
| [`field-scan-2026-10-01.md`](field-scan-2026-10-01.md) | 2026-10-01 | Field scan of five public agent repositories; assessments are not labeled ground truth |
| [`head-to-head-2026-10-08.md`](head-to-head-2026-10-08.md) and [`head-to-head-2026-10-08/`](head-to-head-2026-10-08/) | 2026-10-08 | Synthetic-estate comparison of discovery tools, with its runner scripts, labels and scores; the regressions it found are pinned in `tests/unit/test_benchmark_followups.py` |
| [`evidence-depth-2026-10-14/`](evidence-depth-2026-10-14/README.md) | 2026-10-14 | Implementation and local validation record for the bounded evidence analysis of #220, with a before/after comparison on the author-written ShadowBench estate (no change; not production precision). The generated before/after reports were not committed; provenance hashes and reproduction steps are kept |

Current benchmarks, their harnesses and their limits are indexed in
[benchmarks/README.md](../../benchmarks/README.md).
