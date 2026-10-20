# Benchmarks moved to Nexus ShadowBench

Corpora, historical results, harnesses and benchmark-only tests now live in
[Nexus ShadowBench](https://github.com/aisecnomad/Nexus-ShadowBench). Main pins
that repository as the optional `benchmark-suite` submodule. Normal scanner
installation and regression evaluation need no submodule or network access.
The documented self-scan profile excludes `benchmark-suite` as this separate
CI-validated scope; unrestricted scans still report an unavailable submodule
as incomplete.

```bash
git submodule update --init --depth 1 -- benchmark-suite
python -m tools.benchmark_suite
cd benchmark-suite
python -m tools.verify_migration
python -m pytest -q
```

The required companion CI job checks the exact commit pin and runs the moved
harness tests against the candidate scanner. The weekly discovery benchmark
uses the same pin. Read the companion README before reproducing legacy harnesses
that expect the scanner and harness in one checkout.

Every imported file retains its original bytes, mode, Git blob and SHA-256 in
`MIGRATION.json`, from source commit
`0792106b8d2cc09517f7f4ee2eeabf4f8eb8da2d`. Historical results were not rerun or
regraded. They remain author-generated offline evidence, not independent review
or measured field accuracy. ShadowBench-450 remains an unverified archive.

The small [file-dialect regression corpus](../tools/evaluation/sab_holdout_corpus.json)
remains local, byte-for-byte. The [documentation evidence extract](../tools/benchmark_evidence.json)
retains only fields used by the product guide and chart, with source digests;
the required companion check compares it with the pinned original files.

This migration changes new checkouts. Existing Git history is preserved; it
does not make old full-history clones smaller.
