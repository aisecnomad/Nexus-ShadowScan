"""A connector raising SystemExit or another BaseException is a connector failure, not a process exit."""

from __future__ import annotations

import json
import sys
from importlib.metadata import EntryPoint

import pytest
from click.testing import CliRunner

import shadowscan.connectors as registry
import shadowscan.engine as engine_module
from shadowscan import cli as cli_module
from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex

SECRET = "sk-proj-" + "b" * 40


class _Hard(BaseException):
    """Neither Exception nor KeyboardInterrupt: what a careless SDK may raise."""


def _connector(raiser):
    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label == "bad":
                raiser()
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT, label, label, "repository")]

    return Connector


def _config(parallel: int = 1) -> ScanConfig:
    return ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", label="good"),
            ConnectorSpec("code.filesystem", label="bad"),
        ],
        parallel=parallel,
    )


def _exit_zero():
    raise SystemExit(0)


def _exit_text():
    raise SystemExit(f"fatal: Authorization: Bearer {SECRET}")


def _exit_none():
    raise SystemExit


def _hard():
    raise _Hard(f"token={SECRET}")


@pytest.mark.parametrize("parallel", [1, 2])
@pytest.mark.parametrize("raiser", [_exit_zero, _exit_text, _exit_none, _hard])
def test_connector_baseexception_marks_scan_incomplete_and_keeps_siblings(monkeypatch, raiser, parallel):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))

    result = Engine(_config(parallel), SignatureIndex([])).run()

    assert not result.complete
    assert [finding.title for finding in result.findings] == ["good"]
    failed = [st for st in result.stats if st.errors]
    assert len(failed) == 1 and failed[0].incomplete
    assert SECRET not in json.dumps([st.errors for st in result.stats])


@pytest.mark.parametrize("raiser", [_exit_zero, _hard])
def test_cli_reports_exit_3_with_a_report_when_a_connector_exits(monkeypatch, tmp_path, raiser):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))
    config = tmp_path / "scan.yaml"
    config.write_text(
        "connectors:\n"
        "  - name: code.filesystem\n    label: good\n"
        "  - name: code.filesystem\n    label: bad\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert [finding["title"] for finding in report["findings"]] == ["good"]


def test_keyboard_interrupt_still_aborts_the_scan(monkeypatch):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(interrupt))
    with pytest.raises(KeyboardInterrupt):
        Engine(_config(), SignatureIndex([])).run()


def test_engine_gives_http_clients_the_connector_deadline_and_cancellation(monkeypatch):
    from shadowscan.utils.http import HttpClient

    seen = {}

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            client = HttpClient()
            seen["deadline"], seen["cancelled"] = client.deadline, client.cancelled
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return []

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: Connector)

    Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="x")]), SignatureIndex([])).run()

    assert seen["deadline"] is not None and seen["cancelled"] is not None
    # The worker context is reset afterwards: clients made outside a connector have no limits.
    assert HttpClient().deadline is None and HttpClient().cancelled is None


# A third-party plugin runs its own code when it is imported, and when the
# engine asks its class about caching and credential approval, before
# collection starts. A BaseException there is a connector failure too.

PLUGIN = "code.acme-exit"


@pytest.fixture
def plugin_registry(monkeypatch):
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])


def _install_plugin(monkeypatch, tmp_path, module, source):
    """Install ``source`` as module ``module`` and publish it as the PLUGIN entry point."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / f"{module}.py").write_text(source, encoding="utf-8")
    monkeypatch.syspath_prepend(str(plugins))
    monkeypatch.delitem(sys.modules, module, raising=False)
    entry = EntryPoint(name=PLUGIN, value=f"{module}:Connector", group="shadowscan.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [entry])


def _repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\nopenai\n", encoding="utf-8")
    return repo


def _scan(tmp_path, plugin_options="", extra_options=""):
    config = tmp_path / "scan.yaml"
    config.write_text(
        "options:\n"
        f"  plugins: [{PLUGIN}]\n"
        "  plugin_execution: thread\n"
        "  allow_credential_mixing: true\n"
        f"{extra_options}"
        "connectors:\n"
        f"  - name: code.filesystem\n    path: {_repository(tmp_path)}\n"
        f"  - name: {PLUGIN}\n{plugin_options}",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])
    return result, out


def _assert_plugin_incomplete(result, out, *expected):
    assert result.exit_code == 3, (result.exit_code, result.output, result.exception)
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert SECRET not in json.dumps(report)
    stats = {entry["connector"]: entry for entry in report["stats"]}
    sibling, plugin = stats["code.filesystem"], stats[PLUGIN]
    assert not sibling["incomplete"] and not sibling["errors"]
    assert any(finding["connector"] == "code.filesystem" for finding in report["findings"])
    assert plugin["incomplete"] and plugin["skipped"]
    (error,) = plugin["errors"]
    assert PLUGIN in error and all(text in error for text in expected), error
    return error


_IMPORT_EXITS = {
    "exit-0": ("import sys\nsys.exit(0)\n", "SystemExit"),
    "exit-1": ("import sys\nsys.exit(1)\n", "SystemExit"),
    "exit-text": (f"raise SystemExit('fatal: Authorization: Bearer {SECRET}')\n", "SystemExit"),
    "baseexception": (
        f"class Fatal(BaseException):\n    pass\n\nraise Fatal('token={SECRET}')\n",
        "Fatal",
    ),
}


@pytest.mark.parametrize("case", sorted(_IMPORT_EXITS))
def test_plugin_exiting_at_import_is_an_incomplete_connector(monkeypatch, tmp_path, plugin_registry, case):
    source, exception = _IMPORT_EXITS[case]
    module = f"acme_exit_plugin_{case.replace('-', '_')}"
    _install_plugin(monkeypatch, tmp_path, module, source)

    result, out = _scan(tmp_path)

    error = _assert_plugin_incomplete(result, out, "could not be imported", exception)
    assert module not in sys.modules
    (diagnostic,) = registry.plugin_registry_errors()
    assert diagnostic.entry == PLUGIN and diagnostic.rule == "load-failed"
    assert diagnostic.message in error and SECRET not in diagnostic.message


def test_keyboard_interrupt_at_plugin_import_still_aborts_the_scan(monkeypatch, tmp_path, plugin_registry):
    _install_plugin(monkeypatch, tmp_path, "acme_interrupt_plugin", "raise KeyboardInterrupt\n")
    repository = ConnectorSpec("code.filesystem", {"path": str(_repository(tmp_path))})
    config = ScanConfig(
        connectors=[repository, ConnectorSpec(PLUGIN)],
        plugins=[PLUGIN],
        plugin_execution="thread",
        allow_credential_mixing=True,
    )
    with pytest.raises(KeyboardInterrupt):
        Engine(config, SignatureIndex([])).run()


_PLUGIN_CLASS = """
import sys

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.models import Surface

constructed = False
collected = False


class Meta(type(BaseConnector)):
    {meta}


class Connector(BaseConnector, metaclass=Meta):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Exits from an engine hook."
    config_keys = {{"paths": "roots"}}

    @classmethod
    def {hook}(cls, *args, **kwargs):
        {body}

    def __init__(self, ctx):
        global constructed
        constructed = True
        super().__init__(ctx)

    def collect(self):
        global collected
        collected = True
        yield from ()

    def analyze(self, records):
        yield from ()
"""

_HOOK_EXITS = {
    "approval-exit-0": ("inherits_instance_credentials_approval", "sys.exit(0)", "SystemExit"),
    "approval-exit-text": (
        "inherits_instance_credentials_approval",
        f"raise SystemExit('token={SECRET}')",
        "SystemExit",
    ),
    "split-exit-0": ("cache_roots_separately", "sys.exit(0)", "SystemExit"),
    "split-error": ("cache_roots_separately", f"raise ValueError('token={SECRET}')", "ValueError"),
    "split-connector-error": (
        "cache_roots_separately",
        f"raise ConnectorError('opaque {SECRET}')",
        "ConnectorError",
    ),
}


@pytest.mark.parametrize("case", sorted(_HOOK_EXITS))
def test_plugin_exiting_from_an_engine_hook_is_an_incomplete_connector(
    monkeypatch, tmp_path, plugin_registry, case
):
    hook, body, exception = _HOOK_EXITS[case]
    source = _PLUGIN_CLASS.format(meta="pass", hook=hook, body=body)
    module = f"acme_hook_plugin_{case.replace('-', '_')}"
    _install_plugin(monkeypatch, tmp_path, module, source)
    roots = [tmp_path / "roots" / name for name in ("one", "two")]
    for root in roots:
        root.mkdir(parents=True)

    result, out = _scan(
        tmp_path,
        plugin_options=f"    paths: [{roots[0]}, {roots[1]}]\n",
        extra_options=f"  incremental: true\n  state_dir: {tmp_path / 'state'}\n",
    )

    error = _assert_plugin_incomplete(result, out, f"{hook}() raised {exception}")
    assert error == f"{PLUGIN}: {hook}() raised {exception}"
    assert not sys.modules[module].constructed and not sys.modules[module].collected


@pytest.mark.parametrize(
    "invalid_config,expected",
    [
        ({"duplicate_paths": True}, "labeled paths must resolve to distinct scan roots"),
        ({"root_ids": ["only-one"]}, "root_ids must contain exactly one ID per path"),
    ],
)
def test_failed_builtin_cache_hook_preserves_validation_diagnostics(tmp_path, invalid_config, expected):
    roots = [tmp_path / name for name in ("one", "two")]
    for root in roots:
        root.mkdir()
    config = {"paths": [str(root) for root in roots]}
    if invalid_config.get("duplicate_paths"):
        config["paths"] = [str(roots[0]), str(roots[0])]
    else:
        config.update(invalid_config)
    result = Engine(
        ScanConfig(
            connectors=[ConnectorSpec("code.filesystem", config, label="repository")],
            incremental=True,
            state_dir=str(tmp_path / "state"),
        ),
        SignatureIndex([]),
    ).run()

    assert not result.complete and not result.findings
    (stats,) = result.stats
    assert stats.incomplete and stats.skipped
    assert stats.errors == [f"code.filesystem: {expected}"]


def test_plugin_exiting_while_its_class_is_verified_is_an_incomplete_connector(
    monkeypatch, tmp_path, plugin_registry
):
    # The registry reads the declared attributes; a metaclass property runs plugin code there.
    meta = "@property\n    def description(cls):\n        sys.exit(0)"
    source = _PLUGIN_CLASS.format(meta=meta, hook="cache_roots_separately", body="return False")
    _install_plugin(monkeypatch, tmp_path, "acme_verify_plugin", source)

    result, out = _scan(tmp_path)

    _assert_plugin_incomplete(result, out, "connector lookup raised SystemExit")


_FORGING_PLUGIN = """
from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Finding, Kind, Surface


class Connector(BaseConnector):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Overrides run() to forge a built-in connector's finding."
    config_keys = {"paths": "roots"}

    def collect(self):
        return []

    def analyze(self, records):
        return []

    def run(self):
        # Bypass BaseConnector.run()'s attribution stamp and claim a built-in name.
        self.ctx.examined(1)
        forged = Finding(
            connector="code.filesystem",
            kind=Kind.AGENT,
            surface=Surface.CODE,
            title="forged built-in finding",
            resource="forged",
            resource_type="repo",
        )
        return [forged]
"""


def test_thread_mode_plugin_cannot_report_under_a_builtin_connector_name(monkeypatch, tmp_path):
    """Regression (October 15 review F4): thread-mode plugin findings were not attribution-checked,
    so a plugin overriding run() could report under a built-in connector's name."""
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])
    _install_plugin(monkeypatch, tmp_path, "acme_forging_plugin", _FORGING_PLUGIN)

    result, out = _scan(tmp_path)

    report = json.loads(out.read_text(encoding="utf-8"))
    # The forged finding is re-attributed to the plugin, never left under the built-in name it
    # claimed, so no finding reports under code.filesystem on behalf of the plugin.
    forged = [f for f in report["findings"] if f["title"] == "forged built-in finding"]
    assert forged and all(f["connector"] == PLUGIN for f in forged), [f["connector"] for f in forged]


# The same forgery through analyze(): BaseConnector.run() stamps the plugin's name on it.
_ANALYZE_FORGING_PLUGIN = _FORGING_PLUGIN.replace(
    "    def analyze(self, records):\n        return []\n\n    def run(self):\n"
    "        # Bypass BaseConnector.run()'s attribution stamp and claim a built-in name.\n"
    "        self.ctx.examined(1)\n",
    "    def collect(self):\n        return [{}]\n\n    def analyze(self, records):\n",
).replace("        return [forged]\n", "        yield forged\n")


# The same finding under the plugin's own name, with the built-in finding's id set explicitly, or
# copied with dataclasses.replace from one built under the built-in name: the connector is the
# plugin's, so nothing re-stamps it, and the id is the one the built-in name gives.
_EXPLICIT_ID_PLUGIN = _ANALYZE_FORGING_PLUGIN.replace(
    "        yield forged\n",
    "        yield Finding(\n"
    "            connector=self.name, id=forged.id, kind=forged.kind, surface=forged.surface,\n"
    "            title=forged.title, resource=forged.resource, resource_type=forged.resource_type,\n"
    "        )\n",
)
_REPLACE_PLUGIN = _ANALYZE_FORGING_PLUGIN.replace(
    "        yield forged\n",
    "        import dataclasses\n\n        yield dataclasses.replace(forged, connector=self.name)\n",
)


@pytest.mark.parametrize(
    "source",
    [_FORGING_PLUGIN, _ANALYZE_FORGING_PLUGIN, _EXPLICIT_ID_PLUGIN, _REPLACE_PLUGIN],
    ids=["run", "analyze", "explicit-id", "replace"],
)
def test_a_reattributed_plugin_finding_does_not_keep_the_builtin_id(monkeypatch, tmp_path, source):
    """Regression: the re-stamp changed the connector of a finding a plugin built under a built-in
    name but kept the id that name entered, so it had the id of the built-in connector's own
    finding for the same resource (baselines, diffs and fleet merges key on the id). A finding
    built under the plugin's own name kept any id the plugin gave it in the same way."""
    assert "def run(self)" not in _ANALYZE_FORGING_PLUGIN and "yield forged" in _ANALYZE_FORGING_PLUGIN
    assert _ANALYZE_FORGING_PLUGIN not in {_EXPLICIT_ID_PLUGIN, _REPLACE_PLUGIN}
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])
    _install_plugin(monkeypatch, tmp_path, "acme_forging_plugin", source)

    result, out = _scan(tmp_path)

    report = json.loads(out.read_text(encoding="utf-8"))
    [forged] = [f for f in report["findings"] if f["title"] == "forged built-in finding"]
    shape = {
        "kind": Kind.AGENT,
        "surface": Surface.CODE,
        "title": "t",
        "resource": "forged",
        "resource_type": "repo",
    }
    builtin_id = Finding(connector="code.filesystem", **shape).id
    plugin_id = Finding(connector=PLUGIN, provider=forged["provider"], **shape).id
    assert forged["connector"] == PLUGIN
    assert forged["id"] == plugin_id != builtin_id


_COLLIDING_PLUGIN = """
import dataclasses
import json
import os

from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Evidence, Finding, Kind, Surface

TARGET = json.loads(os.environ["SHADOWSCAN_FORGE_TARGET"])


class Connector(BaseConnector):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Gives its finding the id of a built-in connector's finding."
    config_keys = {"paths": "roots"}

    def collect(self):
        return [{}]

    def analyze(self, records):
        shape = {**TARGET, "surface": Surface(TARGET["surface"]), "kind": Kind.AGENT, "title": "FORGED"}
        claimed = Finding(connector="code.filesystem", tags=["plugin-injected"], **shape)
        if os.environ["SHADOWSCAN_FORGE_MODE"] == "explicit-id":
            forged = Finding(connector=self.name, id=claimed.id, tags=["plugin-injected"], **shape)
        else:
            forged = dataclasses.replace(claimed, connector=self.name)
        forged.add_evidence(Evidence(signal="plugin:forged", description="injected", weight=0.9))
        yield forged
"""


@pytest.mark.parametrize("plugin_first", [True, False], ids=["plugin-first", "plugin-second"])
@pytest.mark.parametrize("mode", ["explicit-id", "replace"])
def test_a_plugin_finding_never_merges_with_the_builtin_finding_it_imitates(
    monkeypatch, tmp_path, index, mode, plugin_first
):
    """Regression: a plugin finding that kept a built-in finding's id merged with that finding: run
    first, the plugin's finding absorbed the built-in one (its title replaced it); run second, the
    plugin's tags and evidence were merged into the built-in finding."""
    repository = ConnectorSpec("code.filesystem", {"path": str(_repository(tmp_path)), "use_git": False})
    alone = Engine(ScanConfig(connectors=[repository]), index).run()
    target = alone.findings[0]
    identity = ("resource", "resource_type", "provider", "account", "region", "identity_discriminator")
    fields = {name: getattr(target, name) for name in identity}
    monkeypatch.setenv("SHADOWSCAN_FORGE_TARGET", json.dumps({**fields, "surface": target.surface.value}))
    monkeypatch.setenv("SHADOWSCAN_FORGE_MODE", mode)
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])
    _install_plugin(
        monkeypatch, tmp_path, f"acme_colliding_plugin_{mode.replace('-', '_')}", _COLLIDING_PLUGIN
    )
    plugin = ConnectorSpec(PLUGIN)
    connectors = [plugin, repository] if plugin_first else [repository, plugin]
    config = ScanConfig(
        connectors=connectors, plugins=[PLUGIN], plugin_execution="thread", allow_credential_mixing=True
    )

    result = Engine(config, index).run()

    assert result.complete, result.stats
    [builtin] = [finding for finding in result.findings if finding.id == target.id]
    assert builtin.connector == "code.filesystem" and builtin.title == target.title
    assert "plugin-injected" not in builtin.tags
    assert all(evidence.signal != "plugin:forged" for evidence in builtin.evidence)
    [forged] = [finding for finding in result.findings if finding.connector == PLUGIN]
    expected = Finding(connector=PLUGIN, surface=target.surface, kind=Kind.AGENT, title="FORGED", **fields).id
    assert forged.id == expected != target.id


# The colliding finding again, with a registry record, from a plugin that then overruns its
# deadline. It holds its worker until the test releases it, then changes the finding it yielded.
_OVERRUNNING_PLUGIN = """
import json
import os
import threading

from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Finding, Kind, Surface

TARGET = json.loads(os.environ["SHADOWSCAN_FORGE_TARGET"])
release = threading.Event()
changed = threading.Event()


class Connector(BaseConnector):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Claims a built-in finding's id and a registry approval, then overruns."
    config_keys = {"paths": "roots"}

    def collect(self):
        return [{}]

    def analyze(self, records):
        shape = {**TARGET, "surface": Surface(TARGET["surface"]), "kind": Kind.AGENT, "title": "FORGED"}
        claimed = Finding(connector="code.filesystem", **shape)
        forged = Finding(connector=self.name, id=claimed.id, tags=["plugin-injected"], **shape)
        forged.metadata["registry_record"] = {"registry": "aws-agent-registry"}
        yield forged
        self.ctx.cancelled.wait(30)
        release.wait(30)
        forged.id = claimed.id
        forged.title = "CHANGED AFTER THE DEADLINE"
        changed.set()
"""


def test_an_overrunning_plugin_surrenders_only_what_a_completed_plugin_could_report(
    monkeypatch, tmp_path, index
):
    """Regression: an expired job's findings were published as the worker left them. A thread-mode
    plugin's finding kept the built-in finding's id it claimed and folded that finding into its own,
    kept a registry record only built-in connectors may emit, and stayed the object the abandoned
    worker could still change after the report was built."""
    repository = ConnectorSpec("code.filesystem", {"path": str(_repository(tmp_path)), "use_git": False})
    target = Engine(ScanConfig(connectors=[repository]), index).run().findings[0]
    identity = ("resource", "resource_type", "provider", "account", "region", "identity_discriminator")
    fields = {name: getattr(target, name) for name in identity}
    monkeypatch.setenv("SHADOWSCAN_FORGE_TARGET", json.dumps({**fields, "surface": target.surface.value}))
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])
    _install_plugin(monkeypatch, tmp_path, "acme_overrunning_plugin", _OVERRUNNING_PLUGIN)
    config = ScanConfig(
        connectors=[ConnectorSpec(PLUGIN), repository],
        plugins=[PLUGIN],
        plugin_execution="thread",
        allow_credential_mixing=True,
        # Long enough for the built-in scan to finish beside the plugin's overrun.
        connector_timeout_seconds=3.0,
        parallel=2,
    )
    try:
        result = Engine(config, index).run()
    finally:
        # Only now may the abandoned worker change the finding it surrendered.
        plugin = sys.modules["acme_overrunning_plugin"]
        plugin.release.set()
    assert plugin.changed.wait(10)

    assert not result.complete
    [builtin] = [finding for finding in result.findings if finding.id == target.id]
    assert builtin.connector == "code.filesystem" and builtin.title == target.title
    assert "plugin-injected" not in builtin.tags
    [forged] = [finding for finding in result.findings if finding.connector == PLUGIN]
    expected = Finding(connector=PLUGIN, surface=target.surface, kind=Kind.AGENT, title="FORGED", **fields).id
    assert forged.id == expected != target.id and forged.title == "FORGED"
    assert all("registry_record" not in finding.metadata for finding in result.findings)
    [stats] = [st for st in result.stats if st.connector == PLUGIN]
    assert stats.findings == 1 and any("registry record metadata ignored on 1" in w for w in stats.warnings)
    assert not any(st.connector == "engine.registries" for st in result.stats)


# A plugin that overruns after it yielded a finding, then changes that finding or is asked about
# its class while the supervisor prepares the surrendered findings. That runs on the supervisor
# thread, outside the worker's isolation, so plugin code raising sys.exit() there ended the scan.
_SURRENDER_EXIT_PLUGIN = """
import sys

from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Finding, Kind, Surface


class Fatal(BaseException):
    pass


def leave(*args, **kwargs):
    {exit}


class Poison:
    # Every operation a copy, a sanitizer pass or a comparison can use ends the process.
    __deepcopy__ = __copy__ = __reduce_ex__ = __reduce__ = __getstate__ = leave
    __repr__ = __str__ = __format__ = __eq__ = __ne__ = __hash__ = __bool__ = leave
    __iter__ = __len__ = __getitem__ = __contains__ = leave


class Meta(type(BaseConnector)):
    {meta}


class Connector(BaseConnector, metaclass=Meta):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Yields a finding, then overruns its deadline."
    config_keys = {{"paths": "roots"}}

    def collect(self):
        return [{{}}]

    def analyze(self, records):
        finding = Finding(
            connector=self.name, surface=Surface.CODE, kind=Kind.AGENT, title="surrendered",
            resource="surrendered", resource_type="file",
        )
        finding.metadata["registry_record"] = {{"registry": "aws-agent-registry"}}
        yield finding
        {after_yield}
        self.ctx.cancelled.wait(30)
"""

_SURRENDER_EXITS = {
    "exit-0": "sys.exit(0)",
    "exit-text": f"raise SystemExit('token={SECRET}')",
    "baseexception": f"raise Fatal('token={SECRET}')",
}


def _scan_overrunning_plugin(monkeypatch, tmp_path, module, source):
    """Scan the repository beside an overrunning thread-mode plugin through the real CLI path."""
    _install_plugin(monkeypatch, tmp_path, module, source)
    exits = []

    def hard_exit(code):
        # The CLI leaves abandoned workers with os._exit; record the code it chose instead.
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(cli_module.os, "_exit", hard_exit)
    # Long enough for the built-in scan to finish beside the plugin's overrun.
    result, out = _scan(tmp_path, extra_options="  connector_timeout_seconds: 3\n  parallel: 2\n")
    assert exits in ([], [3]), exits
    assert result.exit_code == 3, (result.exit_code, result.output, result.exception)
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False and SECRET not in json.dumps(report)
    stats = {entry["connector"]: entry for entry in report["stats"]}
    sibling, plugin = stats["code.filesystem"], stats[PLUGIN]
    assert not sibling["incomplete"] and not sibling["errors"]
    assert any(finding["connector"] == "code.filesystem" for finding in report["findings"])
    assert plugin["incomplete"] and any("deadline exceeded" in error for error in plugin["errors"])
    assert all("registry_record" not in finding["metadata"] for finding in report["findings"])
    return report, plugin


@pytest.mark.parametrize("case", sorted(_SURRENDER_EXITS))
def test_a_surrendered_finding_that_exits_when_copied_is_omitted_not_a_clean_exit(
    monkeypatch, tmp_path, plugin_registry, case
):
    """Regression: _surrender copied an overrunning thread-mode plugin's findings on the supervisor
    thread under ``except Exception``, so an object the plugin planted in a yielded finding's
    metadata, raising SystemExit(0) from __deepcopy__ or __str__, ended the scan with exit 0 and
    no report."""
    source = _SURRENDER_EXIT_PLUGIN.format(
        exit=_SURRENDER_EXITS[case], meta="pass", after_yield='finding.metadata["planted"] = Poison()'
    )
    module = f"acme_poison_plugin_{case.replace('-', '_')}"

    report, plugin = _scan_overrunning_plugin(monkeypatch, tmp_path, module, source)

    assert plugin["findings"] == 0
    assert "1 finding(s) completed before the deadline omitted: not readable" in plugin["errors"]
    assert all(finding["title"] != "surrendered" for finding in report["findings"])


@pytest.mark.parametrize("case", sorted(_SURRENDER_EXITS))
def test_a_plugin_class_that_exits_when_asked_for_its_records_keeps_none(
    monkeypatch, tmp_path, plugin_registry, case
):
    """Regression: the surrendered findings' registry records were withheld by reading the plugin
    class's declarations on the supervisor thread, where a metaclass property raising SystemExit
    ended the scan with exit 0 and no report."""
    meta = f"@property\n    def emits_registry_records(cls):\n        {_SURRENDER_EXITS[case]}"
    source = _SURRENDER_EXIT_PLUGIN.format(exit=_SURRENDER_EXITS[case], meta=meta, after_yield="pass")
    module = f"acme_declaring_plugin_{case.replace('-', '_')}"

    report, plugin = _scan_overrunning_plugin(monkeypatch, tmp_path, module, source)

    assert plugin["findings"] == 1
    [surrendered] = [finding for finding in report["findings"] if finding["connector"] == PLUGIN]
    assert surrendered["title"] == "surrendered"
    assert any("registry record metadata ignored on 1" in warning for warning in plugin["warnings"])
