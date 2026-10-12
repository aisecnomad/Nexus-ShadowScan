"""Verify a committed corpus: it loads, validates, and matches the generator at its recorded seed.

``python -m tools.shadowbench.synthetic verify --corpus corpus.json [--regenerate]``

Prints the corpus SHA-256 and the generator digest. With ``--regenerate`` the
corpus is rebuilt from the generator sources at the recorded seed and compared
byte for byte (ignoring the ``created`` stamp), so anyone can confirm the
committed inputs are exactly what the committed code produces.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from tools.shadowbench.synthetic.corpus import corpus_digest, load_corpus
from tools.shadowbench.synthetic.generate import build, generator_digest


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
        # The code surface is the fixed pinned set; every other surface holds
        # per_surface generated cases, so the count is read from one of those.
        generated = Counter(case.surface for case in corpus.cases if case.surface != "code")
        per_surface = max(generated.values()) if generated else 0
        rebuilt = [c.to_json() for c in build(corpus.seed, per_surface)]
        stored = json.loads(args.corpus.read_text(encoding="utf-8"))["cases"]
        if rebuilt == stored:
            # Identical output is what the check is for: changed sources that
            # still write the same corpus (a move, a comment) are not a drift.
            print("regenerated corpus is identical")
            status = 0
        else:
            print("regenerated corpus DIFFERS from the stored one")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
