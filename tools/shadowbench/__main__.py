"""``python -m tools.shadowbench <command>``: generate, verify, run, score, report."""

from __future__ import annotations

import sys

from tools.shadowbench import generate, pdf_report, report, runner, score, verify

COMMANDS = {
    "generate": generate.main,
    "verify": verify.main,
    "run": runner.main,
    "score": score.main,
    "report": report.main,
    "pdf": pdf_report.main,
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print(f"usage: python -m tools.shadowbench {{{'|'.join(COMMANDS)}}} ...", file=sys.stderr)
        return 2
    return COMMANDS[args[0]](args[1:])


if __name__ == "__main__":
    sys.exit(main())
