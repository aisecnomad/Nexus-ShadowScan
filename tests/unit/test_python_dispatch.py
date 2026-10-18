"""Local dispatch recognition is bounded and requires concrete source bindings."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from shadowscan.connectors.code import python_dispatch as dispatch

TABLE = """from pathlib import Path
import json
NOTES = Path("notes")
def read_note(version):
    path = NOTES / f"{version}.md"
    return path.read_text()
def run_tool(name, args):
    handlers = {"read_note": read_note}
    if name not in handlers:
        return json.dumps({"error": "unknown tool"})
    try:
        return json.dumps(handlers[name](**args))
    except Exception as exc:
        return json.dumps({"error": str(exc)})
"""

HTTP = """import httpx
def dispatch(name, args):
    with httpx.Client(base_url="https://example.invalid", timeout=10) as http:
        if name == "get_invoice":
            return http.get(f"/invoices/{args['number']}").json()
        if name == "flag_for_review":
            r = http.post("/reviews", json=args)
            return {"status": r.status_code}
    return {"error": "unknown tool"}
"""


def _resolve(source: str, symbol: str = "run_tool") -> bool:
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", source)
    return index.resolver(".")("tools", symbol)


@pytest.mark.parametrize(
    "case_id,module,symbol",
    [
        ("python-openai-tool-loop-script", "tools", "run_tool"),
        ("litellm-proxy-docker-worker", "worker.tools", "dispatch"),
    ],
)
def test_realistic_sources_resolve_without_importing_or_executing(case_id, module, symbol):
    corpus = json.loads((Path(__file__).parents[2] / "tools/evaluation/realistic_corpus.json").read_text())
    case = next(case for case in corpus["cases"] if case["id"] == case_id)
    index = dispatch.PythonDispatches()
    for path, source in case["files"].items():
        index.add(".", path, source)
    assert index.resolver(".")(module, symbol)
    assert not index.resolver("other-project")(module, symbol)
    assert not index.resolver(".")(module, "missing")


@pytest.mark.parametrize(
    "source",
    [
        TABLE,
        TABLE.replace("Path", "Folder").replace(
            "from pathlib import Folder", "from pathlib import Path as Folder"
        ),
        TABLE.replace("import json", "from json import dumps").replace("json.dumps", "dumps"),
        TABLE.replace("handlers =", "handlers: dict ="),
        TABLE.replace(
            '    if name not in handlers:\n        return json.dumps({"error": "unknown tool"})\n', ""
        ),
        TABLE.replace("return json.dumps(handlers[name](**args))", "return handlers[name](**args)"),
        TABLE.replace(
            "def run_tool(name, args):", 'def run_tool(name, args):\n    """Dispatch the requested tool."""'
        ),
    ],
)
def test_literal_table_with_bound_local_file_handlers(source):
    assert _resolve(source)


@pytest.mark.parametrize(
    "old,new",
    [
        ("def run_tool", "@wrapper\ndef run_tool"),
        ("def read_note", "@wrapper\ndef read_note"),
        ("name, args", "name, args, extra"),
        ("name, args", "name, args=None"),
        ("name, args", "name, *args"),
        ("name, args", "name, **args"),
        ("name, args", "name, *, args"),
        ('handlers = {"read_note": read_note}', 'handlers = {"read_note": unknown}'),
        (
            'handlers = {"read_note": read_note}',
            'handlers = {"read_note": read_note, "read_note": read_note}',
        ),
        ('handlers = {"read_note": read_note}', "handlers = {1: read_note}"),
        ('handlers = {"read_note": read_note}', "handlers = {}"),
        ("handlers[name](**args)", "handlers[other](**args)"),
        ("handlers[name](**args)", "handlers[name](args)"),
        ("handlers[name](**args)", "unknown(name, args)"),
        ("handlers[name](**args)", "print(name, args)"),
        ("handlers[name](**args)", "handlers[name](**other)"),
        ("json.dumps(handlers[name](**args))", "json.dumps(handlers[name](**args), indent=2)"),
        ("    handlers =", "    name = 'fixed'\n    handlers ="),
        ("    handlers =", "    args = {}\n    handlers ="),
        ("    handlers =", "    args['number'] = 42\n    handlers ="),
        ("    handlers =", "    del args\n    handlers ="),
        ("    handlers =", "    return 'nothing'\n    handlers ="),
        ("    handlers =", "    raise RuntimeError()\n    handlers ="),
        ("    try:", "    handlers.clear()\n    try:"),
        ("except Exception as exc:", "except Exception as args:"),
        ("    handlers =", "    import json\n    handlers ="),
        ("    handlers =", "    global NOTES\n    handlers ="),
        ("    handlers =", "    def nested(): pass\n    handlers ="),
        ("    handlers =", "    json.dumps = fake\n    handlers ="),
        ("    handlers =", "    handlers = {}\n    handlers ="),
        ("from pathlib import Path", "from pathlib import *"),
        ("from pathlib import Path", "from .pathlib import Path"),
        ("return path.read_text()", "print(version)"),
        ("return path.read_text()", "return unknown(version)"),
        ("return path.read_text()", "return lambda: path.read_text()"),
        ("return path.read_text()", "return (path.read_text() for n in [])"),
        ("return path.read_text()", "return None\n    return path.read_text()"),
        ("return path.read_text()", "if False:\n        return path.read_text()"),
        ("return path.read_text()", "return False and path.read_text()"),
        ("return path.read_text()", "return path.read_text() if False else None"),
        ("    path =", "    Path = fake\n    path ="),
        ("    path =", "    NOTES = fake\n    path ="),
        ("path = NOTES", "path = other"),
        ("NOTES = Path", "NOTES = unknown"),
        ("NOTES = Path", "NOTES = (side_effect := Path)"),
    ],
)
def test_table_rejects_dead_code_unknown_handlers_and_rebinding(old, new):
    assert not _resolve(TABLE.replace(old, new))


@pytest.mark.parametrize(
    "suffix",
    [
        "\nrun_tool = fake\n",
        "\ndef run_tool(name, args): return None\n",
        "\nread_note = fake\n",
        "\njson = fake\n",
        "\nNOTES = fake\n",
        "\nside_effect()\n",
        "\nif True:\n    run_tool = fake\n",
        "\nclass run_tool: pass\n",
        "\ndef mutate():\n    global run_tool\n    run_tool = fake\n",
    ],
)
def test_module_overwrites_and_import_time_execution_are_not_proof(suffix):
    assert not _resolve(TABLE + suffix)


@pytest.mark.parametrize(
    "source",
    [
        HTTP,
        HTTP.replace("import httpx", "import httpx as web").replace("httpx.Client", "web.Client"),
        HTTP.replace("import httpx", "from httpx import Client").replace("httpx.Client", "Client"),
        HTTP.replace("http.post", "http.patch"),
    ],
)
def test_http_dispatch_requires_name_selection_and_argument_flow(source):
    assert _resolve(source, "dispatch")


@pytest.mark.parametrize(
    "old,new",
    [
        ("httpx.Client", "unknown.Client"),
        ("httpx.Client", "httpx.AsyncClient"),
        ("as http:", "as args:"),
        ("as http:", "as httpx:"),
        ("as http:", "as http, other() as extra:"),
        ("timeout=10", "timeout=unknown()"),
        ('base_url="https://example.invalid"', "unknown()"),
        ('if name == "get_invoice":', 'if other == "get_invoice":'),
        ('if name == "get_invoice":', 'if name != "get_invoice":'),
        ('if name == "get_invoice":', 'if name == "":'),
        ('if name == "get_invoice":', "if False:"),
        ('if name == "get_invoice":', 'if name == "get_invoice" == other:'),
        ("http.get", "other.get"),
        ("http.get", "http.log"),
        ("args['number']", "fixed_number"),
        ("args['number']", "unknown(args)"),
        (".json()", ".json(extra)"),
        (".json()", ".text()"),
        ("r = http.post", "args = http.post"),
        ('return {"status": r.status_code}', 'return {"status": 200}'),
        ('return {"status": r.status_code}', "return unknown(r)"),
        ("r = http.post", "print(name)\n            r = http.post"),
        ("    with httpx", "    name = 'fixed'\n    with httpx"),
        ("    with httpx", "    return {}\n    with httpx"),
    ],
)
def test_http_dispatch_rejects_wrong_bindings_unknown_calls_and_dead_code(old, new):
    assert not _resolve(HTTP.replace(old, new), "dispatch")


def test_finally_cannot_replace_dispatch_result():
    assert not _resolve(TABLE + '    finally:\n        return "suppressed"\n')


def test_package_and_relative_module_resolution_and_collision():
    index = dispatch.PythonDispatches()
    index.add(".", "worker/tools.py", HTTP)
    index.add(".", "worker/__init__.py", "")
    assert index.resolver(".", "worker/main.py")(".tools", "dispatch")
    assert index.resolver(".", "worker/__init__.py")(".tools", "dispatch")
    assert index.resolver(".", "worker/sub/main.py")("..tools", "dispatch")
    assert not index.resolver(".", "main.py")("..tools", "dispatch")
    assert not index.resolver(".")("tools", "dispatch")
    index.add(".", "worker/tools/__init__.py", "")
    assert not index.resolver(".")("worker.tools", "dispatch")


@pytest.mark.parametrize("relative", ["/tools.py", "../tools.py", "tools.js", "bad-name.py"])
def test_invalid_module_paths_cannot_supply_proof(relative):
    index = dispatch.PythonDispatches()
    index.add(".", relative, TABLE)
    assert not index.resolver(".")("tools", "run_tool")


def test_invalid_python_is_plain_non_match():
    assert not _resolve(TABLE + "[incomplete")


@pytest.mark.parametrize(
    "limit", ["MAX_FILES", "MAX_TOTAL_BYTES", "MAX_SOURCE_BYTES", "MAX_AST_NODES", "MAX_TOTAL_NODES"]
)
def test_budget_exhaustion_is_explicit_only_when_affected_helper_is_resolved(monkeypatch, limit):
    monkeypatch.setattr(dispatch, limit, 1)
    index = dispatch.PythonDispatches()
    if limit == "MAX_FILES":
        index.add(".", "other.py", TABLE)
    index.add(".", "tools.py", TABLE)
    assert not index.resolver(".")("unrelated", "run_tool")
    with pytest.raises(dispatch.DispatchLimitError):
        index.resolver(".")("tools", "run_tool")
    with pytest.raises(dispatch.DispatchLimitError):
        index.resolver(".")("tools", "run_tool")


def test_irrelevant_files_do_not_consume_source_budget(monkeypatch):
    monkeypatch.setattr(dispatch, "MAX_FILES", 1)
    index = dispatch.PythonDispatches()
    for number in range(20):
        index.add(".", f"plain{number}.py", "def constant(): return 1\n")
    index.add(".", "tools.py", TABLE)
    assert index.resolver(".")("tools", "run_tool")


@pytest.mark.parametrize("error", [RecursionError, MemoryError])
def test_parser_resource_failure_is_a_coverage_gap(monkeypatch, error):
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", TABLE)

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(ast, "parse", fail)
    with pytest.raises(dispatch.DispatchLimitError):
        index.resolver(".")("tools", "run_tool")


def test_ambiguous_module_remains_non_match_after_budget_failure(monkeypatch):
    monkeypatch.setattr(dispatch, "MAX_SOURCE_BYTES", 1)
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", TABLE)
    index.add(".", "tools/__init__.py", "")
    assert not index.resolver(".")("tools", "run_tool")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("from tools import run_tool", True),
        ("from .tools import run_tool", True),
        ("from tools import *", False),
        ("import tools", False),
        ("from cloud import run_tool", False),
        ("from tools import (", True),
        ("return 1", False),
    ],
)
def test_import_candidate_check(text, expected):
    assert dispatch.has_dispatch_import(text, lambda name: name.lstrip(".") == "tools") is expected


@pytest.mark.parametrize(
    "module,source,symbol",
    [
        ("httpx", HTTP, "dispatch"),
        ("json", TABLE, "run_tool"),
        ("pathlib", TABLE, "run_tool"),
    ],
)
@pytest.mark.parametrize("local_path", ["{module}.py", "{module}/__init__.py", "{module}/unread.bin"])
def test_local_modules_and_unread_packages_cannot_spoof_external_imports(module, source, symbol, local_path):
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", source)
    assert index.resolver(".")("tools", symbol)
    index.note_path(".", local_path.format(module=module))
    # This remains false even when the helper was parsed before the shadow.
    assert not index.resolver(".")("tools", symbol)


def test_nested_project_paths_are_scoped_and_normalized():
    index = dispatch.PythonDispatches()
    index.add("nested", "nested/worker/tools.py", HTTP)
    index.add("other", "other/worker/tools.py", "")
    assert index.resolver("nested", "nested/worker/main.py")("worker.tools", "dispatch")
    assert index.resolver("nested", "nested/worker/main.py")(".tools", "dispatch")
    assert not index.resolver("other", "other/worker/main.py")("worker.tools", "dispatch")
    index.add("nested", "outside/tools.py", TABLE)
    assert not index.resolver("nested", "outside/main.py")("tools", "run_tool")


def test_unread_directory_member_blocks_module_package_collision():
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", TABLE)
    index.note_path(".", "tools/unread.bin")
    assert not index.resolver(".")("tools", "run_tool")


def test_conditional_path_reassignment_cannot_supply_file_handler_proof():
    source = TABLE.replace(
        "    return path.read_text()", "    if flag:\n        path = unknown()\n    return path.read_text()"
    )
    assert not _resolve(source)


def test_relative_import_candidate_does_not_use_absolute_import_predicate():
    def absolute_only(module):
        assert not module.startswith(".")
        return False

    assert dispatch.has_dispatch_import("from .models import Model", absolute_only)


def test_unrelated_relative_import_stays_complete(tmp_path, run_connector):
    (tmp_path / "app.py").write_text("from .models import Model\nresult = Model()\n")
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False
    )
    assert not context.stats.incomplete, context.stats.errors
    assert not findings


def test_handler_parameter_cannot_impersonate_global_path():
    source = TABLE.replace("def read_note(version):", "def read_note(NOTES):")
    assert not _resolve(source)


@pytest.mark.parametrize("replacement", ["(args if False else {})", "(False and args)"])
def test_dead_argument_expression_cannot_prove_argument_flow(replacement):
    assert not _resolve(HTTP.replace("json=args", f"json={replacement}"), "dispatch")


@pytest.mark.parametrize(
    "prefix",
    [
        "    try:\n        raise ValueError()\n    except ValueError as path:\n        pass\n",
        "    if True:\n        return None\n",
        "    hidden = (path := fake)\n",
        "    match value:\n        case {'key': path}:\n            pass\n",
    ],
)
def test_handler_dead_code_and_captured_aliases_cannot_supply_proof(prefix):
    source = TABLE.replace("    return path.read_text()", prefix + "    return path.read_text()")
    assert not _resolve(source)


def test_analysis_resource_failure_remains_explicit_for_affected_consumer(monkeypatch):
    index = dispatch.PythonDispatches()
    index.add(".", "tools.py", TABLE)

    def fail(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(dispatch._Module, "dispatches", fail)
    with pytest.raises(dispatch.DispatchLimitError):
        index.resolver(".")("tools", "run_tool")
    assert not index.resolver(".")("missing", "run_tool")
