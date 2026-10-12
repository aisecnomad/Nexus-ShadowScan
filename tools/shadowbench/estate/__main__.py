"""``python -m tools.shadowbench.estate <command>``; the commands are in ``cli.py``."""

from __future__ import annotations

import sys

from tools.shadowbench.estate.cli import main

if __name__ == "__main__":
    sys.exit(main())
