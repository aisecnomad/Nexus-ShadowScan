"""CLI entry point: ``python -m freight_crew.main < quotes.json``."""

import json
import sys

from freight_crew.crew import build_crew


def main() -> int:
    quotes = json.load(sys.stdin)
    result = build_crew().kickoff(inputs={"quotes": quotes})
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
