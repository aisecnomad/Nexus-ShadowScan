"""Vercel AI SDK dispatch needs executable tools or an enabled multi-step loop.

AI SDK 5 and later run tools in a loop only past the first step (``stopWhen``;
AI SDK 7 renamed ``stepCountIs`` to ``isStepCount``), AI SDK 4 with ``maxSteps``.
The tools of such a loop are usually imported definitions, not inline
``tool({ execute })`` calls, so the loop shape itself establishes the agent.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from shadowscan.connectors.code import file_scan, javascript_imports, source_semantics
from shadowscan.models import Kind

TOOLS = """import { tool } from "ai";
import { z } from "zod";

export const getWeather = tool({
  description: "Current weather for a city",
  inputSchema: z.object({ city: z.string() }),
  execute: async ({ city }) => ({ city, celsius: 21 }),
});
"""


def _project(tmp_path, run_connector, source):
    (tmp_path / "route.ts").write_text(source)
    (tmp_path / "tools.ts").write_text(TOOLS)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(f for f in findings if f.resource_type == "project")


def _route(imports: str, options: str, call: str = "streamText") -> str:
    return (
        f'import {{ {imports} }} from "ai";\n'
        'import { getWeather } from "./tools";\n\n'
        "export async function POST(request) {\n"
        "  const { messages } = await request.json();\n"
        f"  const result = {call}({{\n    model,\n    messages,\n    {options}\n  }});\n"
        "  return result.toUIMessageStreamResponse();\n"
        "}\n"
    )


@pytest.mark.parametrize(
    ("imports", "options"),
    [
        # AI SDK 7, as in a current chat route with imported tools.
        ("isStepCount, streamText", "stopWhen: isStepCount(5),\n    tools: { getWeather },"),
        ("stepCountIs, streamText", "tools: { getWeather },\n    stopWhen: stepCountIs(10),"),
        ("hasToolCall, streamText", "tools: { getWeather },\n    stopWhen: hasToolCall('finalAnswer'),"),
        (
            "hasToolCall, isStepCount, streamText",
            "tools: toolSet,\n    stopWhen: [isStepCount(8), hasToolCall('done')],",
        ),
        ("streamText", "tools: { weather: getWeather },\n    stopWhen: stopCondition,"),
        # AI SDK 4.
        ("streamText", "tools: { getWeather },\n    maxSteps: 5,"),
        ("streamText", "tools: { getWeather },\n    maxSteps: MAX_STEPS,"),
        # Callbacks written as methods, nested spreads and a dynamic tool
        # selection do not hide the loop.
        (
            "isStepCount, streamText",
            "activeTools: reasoning ? [] : ['getWeather'],\n"
            "    onFinish() {\n      record();\n    },\n"
            "    async onError({ error }) {\n      report(error);\n    },\n"
            "    providerOptions: { ...(order && { gateway: { order } }) },\n"
            "    stopWhen: isStepCount(5),\n"
            "    tools: { getWeather, lookup: lookupTool({ session }) },",
        ),
    ],
)
def test_multi_step_tool_loop_is_an_agent(tmp_path, run_connector, imports, options):
    finding = _project(tmp_path, run_connector, _route(imports, options))
    assert finding.kind == Kind.AGENT
    assert "framework.vercel-ai-sdk" in finding.frameworks
    assert "tool-use" in finding.capabilities
    assert any("multi-step tool loop" in e.description for e in finding.evidence)


def test_generate_text_and_namespace_imports_are_resolved(tmp_path, run_connector):
    source = (
        'import * as ai from "ai";\n'
        'import { getWeather } from "./tools";\n'
        "const { text } = await ai.generateText({ model, prompt, tools: { getWeather }, "
        "stopWhen: ai.isStepCount(4) });\n"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT and "tool-use" in finding.capabilities


@pytest.mark.parametrize(
    ("imports", "options"),
    [
        # A plain chat route: one model call, no tools.
        ("streamText", "temperature: 0.2,"),
        # Several steps without tools add nothing for the model to call.
        ("isStepCount, streamText", "stopWhen: isStepCount(5),"),
        ("isStepCount, streamText", "tools: {},\n    stopWhen: isStepCount(5),"),
        ("isStepCount, streamText", "tools: undefined,\n    stopWhen: isStepCount(5),"),
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    toolChoice: 'none',",
        ),
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    activeTools: [],",
        ),
        # A later spread can replace the stop condition and the tools.
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    ...overrides,",
        ),
    ],
)
def test_single_step_or_toolless_calls_stay_sdk_usage(tmp_path, run_connector, imports, options):
    finding = _project(tmp_path, run_connector, _route(imports, options))
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "framework.vercel-ai-sdk" in finding.frameworks
    assert "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    ("imports", "options"),
    [
        ("streamText", "tools: { getWeather },"),
        ("isStepCount, streamText", "tools: { getWeather }, stopWhen: isStepCount(1),"),
        ("streamText", "tools: { weather: getWeather }, maxSteps: 1,"),
        ("streamText", "tools: { getWeather }, stopWhen: undefined,"),
        ("streamText", "tools: { getWeather }, prompt: 'stopWhen: isStepCount(5), maxSteps: 9',"),
    ],
)
def test_single_step_imported_execution_is_dispatch(tmp_path, run_connector, imports, options):
    finding = _project(tmp_path, run_connector, _route(imports, options))
    assert finding.kind == Kind.AGENT and "tool-use" in finding.capabilities


def test_a_local_function_named_like_the_sdk_is_not_bound(tmp_path, run_connector):
    source = _route("generateText", "tools: { getWeather },\n    stopWhen: isStepCount(5),").replace(
        "export async function POST", "const streamText = (options) => options;\nexport async function POST"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE


def test_options_built_elsewhere_are_not_read(tmp_path, run_connector):
    # The options object is not inline, so neither its tools nor its stop condition is known.
    source = (
        'import { isStepCount, streamText } from "ai";\n'
        'import { getWeather } from "./tools";\n'
        "const options = { model, tools: { getWeather }, stopWhen: isStepCount(5) };\n"
        "export const result = streamText(options);\n"
    )
    assert _project(tmp_path, run_connector, source).kind == Kind.FRAMEWORK_USAGE


@pytest.mark.parametrize("name", ["ToolLoopAgent", "Agent"])
def test_agent_classes_bound_to_the_sdk_are_agents(tmp_path, run_connector, name):
    source = (
        f'import {{ {name}, isStepCount }} from "ai";\n'
        'import { getWeather } from "./tools";\n'
        f"export const assistant = new {name}({{ model, tools: {{ getWeather }}, stopWhen: isStepCount(20) }});\n"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT


def test_signature_names_the_ai_sdk_7_stop_conditions(index):
    for text in ("stopWhen: isStepCount(5)", "stopWhen: stepCountIs(5)", "stopWhen: [hasToolCall('x')]"):
        matches = [
            m for m in index.match_code(text, "javascript") if m.signature_id == "framework.vercel-ai-sdk"
        ]
        assert matches and all(m.agent_indicator for m in matches), text


def _imported_project(tmp_path, run_connector, files, **config):
    for relative, source in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False, **config)


def _imported_route(module="./tools", tool="getWeather", options=""):
    return (
        'import { generateText } from "ai";\n'
        f'import {{ getWeather as {tool} }} from "{module}";\n'
        f"export const result = generateText({{model, tools: {{ weather: {tool} }}, {options}}});\n"
    )


def test_configured_import_fixture_has_executable_provenance(tmp_path, run_connector):
    fixture = Path(__file__).parents[1] / "fixtures/code/vercel_imports"
    shutil.copytree(fixture, tmp_path, dirs_exist_ok=True)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "tool-use" in f.capabilities for f in findings)


@pytest.mark.production_budgets
def test_ordinary_export_bundle_does_not_rescan_each_literal_for_shadowing(
    tmp_path, run_connector, monkeypatch
):
    checked = []
    original = source_semantics._drop_uncertain_bindings

    def record(bindings, *args):
        checked.extend(bindings)
        return original(bindings, *args)

    monkeypatch.setattr(source_semantics, "_drop_uncertain_bindings", record)
    source = "const base = import.meta.env.BASE_URL;\n" + "".join(
        f'export const k{number} = "label_{number}";\n' for number in range(500)
    )
    findings, ctx = _imported_project(tmp_path, run_connector, {"src/app.js": source})
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not findings
    assert not checked, "nonexecutable literals need no per-name whole-module shadow analysis"


@pytest.mark.parametrize(
    "module,path", [("./tools", "tools.ts"), ("./tools.js", "tools.ts"), ("./tools", "tools/index.ts")]
)
@pytest.mark.parametrize("name", ["getWeather", "forecast"])
def test_relative_imports_follow_only_an_observed_executable_definition(
    tmp_path, run_connector, module, path, name
):
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": _imported_route(module, name), path: TOOLS}
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "tool-use" in f.capabilities for f in findings)


@pytest.mark.parametrize(
    "definition",
    [
        'import { tool as fn } from "ai";\nexport const getWeather = fn({execute: async () => 1});\n',
        'import * as sdk from "ai";\nexport const getWeather = sdk.tool({execute: async () => 1});\n',
        "export const getWeather = {execute: async () => 1};\n",
    ],
)
def test_imported_definitions_share_inline_callback_semantics(tmp_path, run_connector, definition):
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": _imported_route(), "tools.ts": definition}
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "definition",
    [
        'import { tool } from "ai";\nexport const getWeather = tool({description: "schema only"});\n',
        'import { tool } from "ai";\nexport const getWeather = tool({execute: undefined});\n',
        'import { tool } from "other-sdk";\nexport const getWeather = tool({execute: async () => 1});\n',
        'import { tool } from "ai";\ntool = unrelated;\nexport const getWeather = tool({execute: async () => 1});\n',
        TOOLS + "getWeather.execute = undefined;\n",
        TOOLS + "function replace(getWeather) { return getWeather; }\n",
        'import { tool } from "ai";\nif (false) { export const getWeather = tool({execute: async () => 1}); }\n',
        'import { tool } from "ai"\nexport const getWeather = tool({execute: async () => 1})\n',
        'import { tool } from "ai";\nexport let getWeather = tool({execute: async () => 1});\n',
    ],
)
def test_unknown_mutable_shadowed_dead_or_semicolonless_exports_do_not_prove_dispatch(
    tmp_path, run_connector, definition
):
    # Semicolonless module statements remain deliberately unresolved by this
    # narrow export parser; the source binder still records ordinary SDK usage.
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": _imported_route(), "tools.ts": definition}
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "route",
    [
        _imported_route("external-tools"),
        _imported_route("@/tools"),
        _imported_route("./missing"),
        _imported_route("./tools/"),
        _imported_route("./tools.json"),
        _imported_route() + "getWeather = unrelated;\n",
        _imported_route() + "function replace(getWeather) { return getWeather; }\n",
        _imported_route(options="toolChoice: 'none'"),
        _imported_route(options="activeTools: []"),
        _imported_route(options="activeTools: ['different']"),
        _imported_route(options="...unknownOptions"),
        _imported_route().replace("export const result =", "if (false) { const result =") + "}\n",
    ],
)
def test_consumers_need_resolved_unshadowed_enabled_reachable_tools(tmp_path, run_connector, route):
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": route, "tools.ts": TOOLS, "tools.json.ts": TOOLS}
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


def test_importing_test_only_definition_cannot_promote_production_usage(tmp_path, run_connector):
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": _imported_route("./tests/tools"), "tests/tools.ts": TOOLS}
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False, include_tests=True
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "config,extra",
    [
        ('{"compilerOptions":{"baseUrl":".","paths":{"@/*":["../*"]}}}', {}),
        ('{"compilerOptions":{"paths":{"@/*":["./*","./other/*"]}}}', {}),
        ('{"extends":"./base.json","compilerOptions":{"paths":{"@/*":["./*"]}}}', {}),
        ('{"compilerOptions":{"paths":{"@/*":["./*"]}}}', {"src/tsconfig.json": "{}"}),
        ('{"compilerOptions":{"paths":{"@/*":["./*"]}}}', {"jsconfig.json": "{}"}),
        ('{"compilerOptions":{"paths":{"@/*":["./*"],"ai":["./replacement-sdk"]}}}', {}),
    ],
)
def test_ambiguous_inherited_or_escaping_path_config_does_not_guess(tmp_path, run_connector, config, extra):
    files = {"route.ts": _imported_route("@/tools"), "tools.ts": TOOLS, "tsconfig.json": config, **extra}
    findings, ctx = _imported_project(tmp_path, run_connector, files)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


def test_malformed_path_config_marks_scan_incomplete(tmp_path, run_connector):
    findings, ctx = _imported_project(
        tmp_path,
        run_connector,
        {"route.ts": _imported_route("@/tools"), "tools.ts": TOOLS, "tsconfig.json": '{"compilerOptions":'},
    )
    assert ctx.stats.incomplete
    assert all(f.kind != Kind.AGENT for f in findings)


def test_conflicting_module_candidates_cannot_supply_executable_provenance(tmp_path, run_connector):
    findings, ctx = _imported_project(
        tmp_path,
        run_connector,
        {"route.ts": _imported_route(), "tools.ts": TOOLS, "tools.js": "export const getWeather = {};\n"},
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "override",
    [
        {"ai": ["./fake.ts", "./other.ts"]},
        {"*": ["./*", "./other/*"]},
        {"a*": ["./fake.ts", "./other.ts"]},
        {"a**i": ["./fake.ts"]},
        {"ai": []},
        {"ai": None},
        {"ai": "./fake.ts"},
        {"ai": ["../outside.ts"]},
    ],
)
def test_rejected_or_ambiguous_sdk_mappings_cannot_restore_sdk_provenance(tmp_path, run_connector, override):
    # These local functions return inert objects: their names do not make them
    # the AI SDK, and discarding an unsupported mapping must not hide that fact.
    config = {"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"], **override}}}
    files = {
        "route.ts": _imported_route("@/tools"),
        "tools.ts": TOOLS,
        "fake.ts": "export function tool(value) { return {}; }\nexport function generateText(options) { return {}; }\n",
        "other.ts": "export function tool(value) { return {}; }\n",
        "tsconfig.json": json.dumps(config),
    }
    findings, ctx = _imported_project(tmp_path, run_connector, files)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "path,base",
    [
        ("src/ai.ts", "./src"),
        ("src/ai/index.ts", "./src"),
        ("src/ai/package.json", "./src"),
        ("tests/ai.ts", "./tests"),
        ("src/ai.d.ts", "./src"),
    ],
)
def test_base_url_local_sdk_modules_cannot_supply_package_identity(tmp_path, run_connector, path, base):
    local = (
        '{"name":"local-sdk-imitation"}'
        if path.endswith("package.json")
        else "export const generateText = ordinary;\n"
    )
    findings, ctx = _imported_project(
        tmp_path,
        run_connector,
        {
            "route.ts": _imported_route(),
            "tools.ts": TOOLS,
            "tsconfig.json": json.dumps({"compilerOptions": {"baseUrl": base}}),
            path: local,
        },
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "configuration",
    [
        '{"extends":"./unread-base.json"}',
        '{"compilerOptions":{"paths":{"ai":["./fake.ts","./other.ts"]}}}',
        '{"compilerOptions":{"baseUrl":"../../outside"}}',
        '{"compilerOptions":{"paths":null}}',
    ],
)
@pytest.mark.parametrize("scope", ["consumer", "definition"])
def test_unresolved_relevant_configurations_withhold_imported_tool_provenance(
    tmp_path, run_connector, configuration, scope
):
    if scope == "consumer":
        files = {"src/route.ts": _imported_route("../tools"), "tools.ts": TOOLS}
    else:
        files = {"route.ts": _imported_route("./src/tools"), "src/tools.ts": TOOLS}
    findings, ctx = _imported_project(tmp_path, run_connector, {**files, "src/tsconfig.json": configuration})
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "extra",
    [
        {"src/tsconfig.json": '{"compilerOptions":{"paths":{"unrelated/*":["./*","../other/*"]}}}'},
        {"tsconfig.json": '{"compilerOptions":{"paths":{"unrelated/*":["./*","./other/*"]}}}'},
        {"tsconfig.json": "{}", "jsconfig.json": "{}"},
        {"unused/tsconfig.json": '{"compilerOptions":{"paths":{"ai":["./fake.ts","./other.ts"]}}}'},
        {
            "tsconfig.json": '{"compilerOptions":{"baseUrl":"./src"}}',
            "unrelated/ai.ts": "export const tool = ordinary;\n",
        },
    ],
)
def test_unrelated_alias_ambiguity_does_not_erase_observed_relative_dispatch(tmp_path, run_connector, extra):
    findings, ctx = _imported_project(
        tmp_path,
        run_connector,
        {
            "src/route.ts": _imported_route("../tools"),
            "tools.ts": TOOLS,
            **extra,
        },
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT for f in findings)


@pytest.mark.parametrize(
    "configuration",
    [
        '{"extends":"./private-base.json"}',
        '{"include":["../**/*.ts"],"compilerOptions":{"paths":{"ai":["./fake.ts"]}}}',
        '{"files":["../route.ts"],"compilerOptions":{"paths":{"ai":["./fake.ts"]}}}',
    ],
)
def test_nested_config_with_unknown_or_escaping_selection_can_affect_outer_sources(
    tmp_path, run_connector, configuration
):
    findings, ctx = _imported_project(
        tmp_path,
        run_connector,
        {
            "route.ts": _imported_route(),
            "tools.ts": TOOLS,
            "nested/tsconfig.json": configuration,
        },
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


def test_named_reexport_chain_resolves_and_cycle_stays_unknown(tmp_path, run_connector):
    files = {
        "route.ts": _imported_route("./barrel"),
        "barrel.ts": 'export { getWeather } from "./tools";\n',
        "tools.ts": TOOLS,
    }
    findings, ctx = _imported_project(tmp_path, run_connector, files)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.AGENT for f in findings)
    (tmp_path / "tools.ts").write_text('export { getWeather } from "./barrel";\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)


@pytest.mark.parametrize("limit", ["MAX_CHAIN", "MAX_MODULES", "MAX_MODULE_BYTES", "MAX_EXPORTS"])
def test_import_resolution_limits_mark_incomplete(tmp_path, run_connector, monkeypatch, limit):
    monkeypatch.setattr(javascript_imports, limit, 1)
    files = {
        "route.ts": _imported_route("./barrel"),
        "barrel.ts": 'export { getWeather } from "./tools";\n',
        "tools.ts": TOOLS + "export const extra = {};\n",
    }
    _, ctx = _imported_project(tmp_path, run_connector, files)
    assert ctx.stats.incomplete
    assert any("budget exceeded" in error for error in ctx.stats.errors)


def test_pending_import_limit_retains_usage_and_marks_incomplete(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(file_scan, "MAX_PENDING_FILES", 0)
    findings, ctx = _imported_project(
        tmp_path, run_connector, {"route.ts": _imported_route(), "tools.ts": TOOLS}
    )
    assert ctx.stats.incomplete
    assert all(f.kind != Kind.AGENT for f in findings)


def test_imports_cannot_cross_manifest_projects_or_scan_roots(tmp_path, run_connector):
    _imported_project(
        tmp_path,
        run_connector,
        {
            "app/package.json": '{"name":"consumer"}',
            "app/route.ts": _imported_route("../shared/tools"),
            "shared/package.json": '{"name":"separate-project"}',
            "shared/tools.ts": TOOLS,
        },
    )
    findings, ctx = run_connector(
        "code.filesystem",
        paths=[str(tmp_path / "app"), str(tmp_path / "shared")],
        use_git=False,
        scan_secrets=False,
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert all(f.kind != Kind.AGENT for f in findings)
