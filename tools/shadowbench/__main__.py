"""``python -m tools.shadowbench <track> <command> ...``: run a ShadowBench track's command."""

from __future__ import annotations

import sys
from collections.abc import Callable

from tools.shadowbench.cases.__main__ import main as cases_main
from tools.shadowbench.estate.__main__ import main as estate_main

TRACKS: dict[str, tuple[Callable[[list[str] | None], int], str]] = {
    "cases": (cases_main, "seeded, generated per-surface cases with decoys"),
    "estate": (estate_main, "one authored fictional organization, scored entity by entity"),
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in TRACKS:
        tracks = "\n".join(f"  {name:7s} {summary}" for name, (_, summary) in TRACKS.items())
        print(
            f"usage: python -m tools.shadowbench {{{'|'.join(TRACKS)}}} <command> ...\n\n"
            f"tracks:\n{tracks}\n\nsee benchmarks/shadowbench/README.md",
            file=sys.stderr,
        )
        return 2
    run, _ = TRACKS[args[0]]
    return run(args[1:])


if __name__ == "__main__":
    sys.exit(main())
