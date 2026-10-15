# Authored real-world shapes (SAB)

SAB is this package's short name for its "Real-world Shadow AI Agent Discovery
benchmark" (see [`__init__.py`](__init__.py)). It holds 130 author-written cases ([`corpus.py`](corpus.py)), each modelled on the file
layout of a named public repository and commit, and the harness that runs
ShadowScan's `code.filesystem` connector on them ([`harness.py`](harness.py)).
File contents are rewritten, not copied; 125 cases are repository-shaped and 5
are endpoint-shaped, and an adversarial category targets known ShadowScan
blind spots.

```bash
python -m benchmarks.sab_realworld --output /tmp/sab-run
```

Without `--output` the harness rewrites the committed [`results/`](results/)
in place. The stored run is ShadowScan 0.1.2 on corpus version 2.0.0; see
[`results/REPORT.md`](results/REPORT.md).

The same author wrote the cases, the labels and the scanner, so the results are
regression evidence about these inputs, not field precision or recall.
[`tests/test_sab_realworld_harness.py`](../../tests/test_sab_realworld_harness.py)
covers the harness. [`../README.md`](../README.md) compares this benchmark with
the others.
