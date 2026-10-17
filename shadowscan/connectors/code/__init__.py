"""Code surface: ``code.filesystem`` (local trees), ``code.github`` and ``code.gitlab``.

``filesystem.py`` is the scanner's façade; ``walk.py`` walks the tree, ``file_scan.py`` analyzes
each file, ``project_findings.py`` builds the findings, ``ownership.py`` resolves owners,
``manifests.py`` reads dependency manifests and the ``*_semantics.py``, ``*_tools.py`` and
``*_reachability.py`` helpers analyze source per language. ``github.py`` and ``gitlab.py`` fetch
repositories through ``remote.py``. See ``docs/connectors/code.md`` and "Code scanner internals" in
``docs/architecture.md``.
"""
