"""Verify a committed corpus: it loads, validates, and matches the generator at its recorded seed.

``python -m tools.shadowbench.cases verify --corpus corpus.json [--regenerate]``

Prints the corpus SHA-256 and the generator digest. With ``--regenerate`` the
corpus is rebuilt from the generator sources at the recorded seed and compared
byte for byte (ignoring the ``created`` stamp), so anyone can confirm the
committed inputs are exactly what the committed code produces.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.shadowbench.cases.corpus import corpus_digest, load_corpus
from tools.shadowbench.cases.generate import build, generator_digest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--regenerate", action="store_true")
    args = ap.parse_args(argv)
    corpus = load_corpus(args.corpus)
    print(f"cases {len(corpus.cases)}; seed {corpus.seed}; corpus sha256 {corpus_digest(args.corpus)}")
    current = generator_digest()
    print(f"generator digest recorded {corpus.generator_digest}\ngenerator digest now      {current}")
    status = 0
    if current != corpus.generator_digest:
        print("generator sources changed since this corpus was written")
        status = 1
    if args.regenerate:
        n = len(corpus.cases) // len({c.surface for c in corpus.cases})
        rebuilt = [c.to_json() for c in build(corpus.seed, n)]
        stored = json.loads(args.corpus.read_text(encoding="utf-8"))["cases"]
        if rebuilt == stored:
            print("regenerated corpus is identical")
        else:
            print("regenerated corpus DIFFERS from the stored one")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
