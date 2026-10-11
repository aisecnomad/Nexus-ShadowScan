"""``python -m tools.nine_surface <command>``: generate, verify, run, score, report."""

from __future__ import annotations

import sys

from tools.nine_surface import generate, report, runner, score, verify

COMMANDS = {
    "generate": generate.main,
    "verify": verify.main,
    "run": runner.main,
    "score": score.main,
    "report": report.main,
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print(f"usage: python -m tools.nine_surface {{{'|'.join(COMMANDS)}}} ...", file=sys.stderr)
        return 2
    return COMMANDS[args[0]](args[1:])


if __name__ == "__main__":
    sys.exit(main())
