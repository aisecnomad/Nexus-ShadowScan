"""Fetch the code-surface repositories of the ShadowBench corpus at their pinned commits.

``python tools/shadowbench/synthetic/fetch_code.py DEST`` creates ``DEST/<repo id>`` for every
repository in :data:`tools.shadowbench.synthetic.generate.CODE_REPOS`, using the discovery
benchmark's fetcher (only ``git`` runs; checkouts are detached at the pinned commit).
"""

from __future__ import annotations

import sys
from pathlib import Path

from tools.discovery_benchmark.corpus import load_corpus
from tools.discovery_benchmark.fetch import fetch_repo
from tools.shadowbench.synthetic.generate import CODE_CORPUS, CODE_REPOS


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: fetch_code.py DEST", file=sys.stderr)
        return 2
    dest = Path(argv[0])
    corpus = load_corpus(CODE_CORPUS)
    failures = 0
    for rid in CODE_REPOS:
        try:
            head = fetch_repo(corpus.get(rid), dest / rid)
            print(f"ok {rid} {head}", flush=True)
        except Exception as exc:  # noqa: BLE001 - report every repository, then fail at the end
            failures += 1
            print(f"FAIL {rid}: {exc}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
