"""``python -m tools.shadowbench <track> <command> ...``: run one ShadowBench track.

``synthetic`` commands: generate, verify, run, score, report, pdf.
``estate`` commands: validate, freeze, verify-freeze, run, score, report.
Each track also runs on its own as ``python -m tools.shadowbench.<track>``.
"""

from __future__ import annotations

import importlib
import sys

TRACKS = ("synthetic", "estate")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in TRACKS:
        print(f"usage: python -m tools.shadowbench {{{'|'.join(TRACKS)}}} <command> ...", file=sys.stderr)
        return 2
    # Imported on demand: each track pulls in its own optional dependencies.
    cli = importlib.import_module(f"tools.shadowbench.{args[0]}.cli")
    return int(cli.main(args[1:]))


if __name__ == "__main__":
    sys.exit(main())
