"""Tool adapters for ShadowBench. One module per tool; see ``registry``.

Rules every adapter follows:

* Fail closed. A crash, timeout, missing report, empty output or output that
  does not parse is an ``error`` result, never an ``ok`` result with no
  entities; so is an inventory with an entry that is not an object, and a
  per-target scan that prints no result for one of its targets. A tool that
  says it did not read everything is normalized and flagged with
  ``raw["incomplete"]``.
* Code surface. Code truth holds only ``<category>:<value>`` taxonomy facts,
  so a hit that maps to no fact is dropped, never emitted under another key
  such as ``artifact:<path>``, and counted in ``AdapterResult.out_of_taxonomy``:
  the scorer treats it as an alarm on a negative case, so a tool that alarmed
  on a repository with nothing to find is never credited with a clean scan.
* ``version()`` runs a tool's binary only through ``_probe.run_probe``: a
  scrubbed environment, a throwaway home and a timeout, and as root a drop to
  the stage's unprivileged identity with ``/root`` and ``/home`` hidden.
"""
