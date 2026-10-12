"""Verify a committed corpus: it loads, validates, and matches the generator at its recorded seed.

``python -m tools.shadowbench.cases verify --corpus corpus.json [--regenerate]``

Prints the corpus SHA-256 and the generator digest recorded in the corpus next
to the digest of the current sources. Without ``--regenerate`` the corpus
passes (exit 0) only when the two digests are equal; otherwise verify exits 1
and asks for ``--regenerate``. With ``--regenerate`` the cases are rebuilt from
the current sources at the recorded seed and per-surface count, and the
rebuilt case list is compared with the stored one after both are parsed as
JSON (the header, ``created`` stamp and formatting are not compared). Identical
cases pass even when the digests differ, which happens whenever a source file
moved or changed without changing what it builds; verify says so. Any
difference exits 1.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.corpus import Corpus, corpus_digest, load_corpus
from tools.shadowbench.cases.generate import build, generator_digest


def per_surface(corpus: Corpus) -> int:
    """The ``--per-surface`` a corpus was generated with.

    Corpora written before the header recorded it are inferred from their cases: a surface with
    one modality (endpoint) gets exactly ``per_surface`` cases and one with two gets at most that
    many, so the largest generated surface's count is the value. Code cases are pinned
    repositories, not generated per surface, and do not count.
    """
    if corpus.per_surface is not None:
        return corpus.per_surface
    counts = Counter(c.surface for c in corpus.cases if c.surface != "code")
    return max(counts.values(), default=0)


def _first_difference(rebuilt: list[Any], stored: list[Any]) -> str:
    for i, (new, old) in enumerate(zip(rebuilt, stored, strict=False)):
        if new != old:
            name = old.get("id") if isinstance(old, dict) else None
            return f"first difference at case {i + 1} ({name})"
    return f"{len(rebuilt)} cases rebuilt, {len(stored)} stored"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--regenerate", action="store_true")
    args = ap.parse_args(argv)
    corpus = load_corpus(args.corpus)
    print(f"cases {len(corpus.cases)}; seed {corpus.seed}; corpus sha256 {corpus_digest(args.corpus)}")
    current = generator_digest()
    print(f"generator digest recorded {corpus.generator_digest}\ngenerator digest now      {current}")
    same_sources = current == corpus.generator_digest
    if not same_sources:
        print("generator sources changed since this corpus was written")
    if not args.regenerate:
        if same_sources:
            return 0
        print("rerun with --regenerate to check whether the current sources still build the same cases")
        return 1
    n = per_surface(corpus)
    # Round-trip through JSON so the rebuilt cases compare exactly as they would be written.
    rebuilt = json.loads(json.dumps([c.to_json() for c in build(corpus.seed, n)], ensure_ascii=False))
    stored = json.loads(args.corpus.read_text(encoding="utf-8"))["cases"]
    if rebuilt != stored:
        where = _first_difference(rebuilt, stored)
        print(f"regenerated cases DIFFER from the stored ones (per-surface {n}; {where})")
        return 1
    if same_sources:
        print(f"regenerated cases are identical (per-surface {n})")
    else:
        print(
            f"regenerated cases are identical (per-surface {n}): the sources changed since the corpus "
            "was written but produce the same cases"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
