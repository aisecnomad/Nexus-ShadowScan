"""Cross-file queuing preserves ordinary scanning and real redaction failures."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import file_scan


@pytest.mark.parametrize("provider", [None, "from openai import OpenAI", "from litellm import completion"])
def test_only_provider_consumers_add_nested_dispatch_deferral(tmp_path, run_connector, monkeypatch, provider):
    package = tmp_path / "worker"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "models.py").write_text("class Model:\n    pass\n")
    source = "from worker.models import Model\nvalue = Model()\n"
    if provider:
        source = provider + "\n" + source
    (package / "consumer.py").write_text(source)
    queued = []
    resolve = file_scan.FileScanner.resolve_reexport_sources

    def capture(self, scan):
        queued.extend(item.file.rel for item in scan.reexport_files)
        return resolve(self, scan)

    monkeypatch.setattr(file_scan.FileScanner, "resolve_reexport_sources", capture)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert ("worker/consumer.py" in queued) == bool(provider)


@pytest.mark.parametrize("provider", [False, True])
def test_unrelated_nested_import_does_not_create_an_excerpt_sanitization_obligation(
    tmp_path, run_connector, monkeypatch, provider
):
    package = tmp_path / "worker"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "models.py").write_text("class Model:\n    pass\n")
    source = "from worker.models import Model\nvalue = Model()\n# excerpt-budget-regression\n"
    if provider:
        source = "from openai import OpenAI\n" + source
    (package / "consumer.py").write_text(source)
    redact = file_scan._redacted_source
    redacted = []

    def limited(text, structure):
        if "excerpt-budget-regression" in text:
            redacted.append(True)
            raise file_scan.SanitizationLimitError("synthetic excerpt limit")
        return redact(text, structure)

    monkeypatch.setattr(file_scan, "_redacted_source", limited)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    # A provider import records actual evidence: its real redaction limit must
    # still fail closed. An ordinary module creates no evidence to redact.
    assert bool(redacted) == provider
    assert ctx.stats.incomplete == provider
    assert any("sanitization" in message for message in ctx.stats.errors) == provider
