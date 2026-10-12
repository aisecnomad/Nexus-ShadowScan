"""Tool adapters for ShadowBench. One module per tool; see ``registry``.

Rules every adapter follows:

* Fail closed. A crash, timeout, missing report, empty output or output that
  does not parse is an ``error`` result, never an ``ok`` result with no
  entities. A tool that says it did not read everything is normalized and
  flagged with ``raw["incomplete"]``.
* Code surface. Code truth holds only ``<category>:<value>`` taxonomy facts,
  so a hit that maps to no fact is dropped (and counted in the note), never
  emitted under another key such as ``artifact:<path>``.
* ``version()`` runs a tool's binary only through ``_probe.run_probe``: a
  scrubbed environment, a throwaway home and a timeout.
"""
