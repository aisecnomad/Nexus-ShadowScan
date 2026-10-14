# File-dialect holdout

[`corpus.json`](corpus.json) holds 17 handwritten cases for file dialects and
exposure boundaries that earlier scans missed (for example an OpenClaw gateway
configuration that is configuration, not a running agent). It is a regression
corpus in the `tools.evaluation` format, not a benchmark against other tools,
and it is not independent: its provenance field says so.

`tests/test_evaluation.py::test_sab_holdout_file_corpus_regressions` evaluates
it in every test run, and
`tests/unit/test_signatures.py::test_sab_holdout_file_dialects_are_inventory_only`
pins the signature side of the same file names. The `sab` prefix is shared with
[`../sab_realworld/`](../sab_realworld/README.md); [`../README.md`](../README.md)
lists every benchmark and corpus.
