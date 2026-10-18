"""Cross-file execution proof never follows paths or evaluates scanned JavaScript."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from shadowscan.connectors.code import javascript_project_tools as module
from shadowscan.connectors.code.javascript_project_tools import JavascriptProjectTools, has_local_tool_import
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded
from shadowscan.models import Kind

TOOL = """import { tool } from "ai";
export const lookup = tool({execute: async ({ id }) => ({ id })});
"""
SOURCE = """import { generateText } from "ai";
import { lookup } from "./tools";
export async function answer() {
  return generateText({model, tools: {lookup}});
}
"""
CONFIG = '{"compilerOptions":{"paths":{"@/*":["./*"]}}}'
INLINE = """import { generateText, tool } from "ai";
export const result = generateText({model, tools: {lookup: tool({execute: () => 1})}});
"""


def _matches(index, files, *, source="route.ts", project=".", observed=()):
    resolver = JavascriptProjectTools()
    for path in (*files, *observed):
        resolver.note_path(project, path)
    for path, text in files.items():
        resolver.add(project, path, text, PurePosixPath(path).suffix)
    text = files[source]
    ignored, ambiguous = noncode_ranges(text, "javascript", ".ts")
    assert not ambiguous
    return resolver.matches(index, project, source, text, ignored)


@pytest.mark.parametrize(
    ("path", "specifier"),
    [
        ("tools.ts", "./tools"),
        ("tools.ts", "./tools.js"),
        ("tools/index.ts", "./tools"),
        ("tools.mts", "./tools.mjs"),
        ("tools.cts", "./tools.cjs"),
    ],
)
def test_local_executable_import_resolves(index, path, specifier):
    matches = _matches(index, {path: TOOL, "route.ts": SOURCE.replace("./tools", specifier)})
    assert len(matches) == 1
    assert matches[0].extra["verified_agent"]
    assert matches[0].extra["source_capabilities"] == ["tool-use"]


def test_named_import_aliases_and_namespace_generation(index):
    source = (
        SOURCE.replace("import { generateText }", "import * as sdk")
        .replace("generateText({", "sdk.generateText({")
        .replace("{ lookup }", "{ lookup as fetchOrder }")
        .replace("tools: {lookup}", "tools: {order: fetchOrder}")
    )
    tool = TOOL.replace("{ tool }", "{ tool as createTool }").replace("= tool(", "= createTool(")
    assert _matches(index, {"route.ts": source, "tools.ts": tool})


def test_alias_requires_explicit_configuration(index):
    files = {"lib/route.ts": SOURCE.replace("./tools", "@/lib/tools"), "lib/tools.ts": TOOL}
    assert not _matches(index, files, source="lib/route.ts")
    files["tsconfig.json"] = CONFIG
    assert _matches(index, files, source="lib/route.ts")


def test_jsonc_paths_and_relative_parent_import(index):
    config = '{// a comment\n"compilerOptions":{"paths":{"tools":["src/lib/tools"]}},}'
    files = {
        "src/app/route.ts": SOURCE.replace("./tools", "tools"),
        "src/lib/tools.ts": TOOL,
        "tsconfig.json": config,
    }
    assert _matches(index, files, source="src/app/route.ts")
    files["src/app/route.ts"] = SOURCE.replace("./tools", "../lib/tools")
    assert _matches(index, files, source="src/app/route.ts")


@pytest.mark.parametrize(
    "tool",
    [
        "export const lookup = tool({execute: async () => 1});",
        TOOL.replace('from "ai"', 'from "unrelated"'),
        TOOL.replace("execute:", "description:"),
        TOOL.replace("async ({ id }) => ({ id })", "undefined"),
        TOOL.replace("async ({ id }) => ({ id })", "(function () {})()"),
        TOOL.replace("export const", "const"),
        TOOL.replace("export const", "export let"),
        TOOL + "lookup.execute = undefined;\n",
        TOOL + "lookup['execute'] = undefined;\n",
        TOOL + "Object.assign(lookup, {execute: undefined});\n",
        TOOL + "unknown(lookup);\n",
        TOOL + "const alias = lookup; alias.execute = undefined;\n",
        TOOL.replace("export const lookup", "tool = replacement; export const lookup"),
        TOOL.replace("export const lookup", "if (false) { const lookup") + "}\n",
        'export { lookup } from "./other";',
        TOOL.replace("= tool({", "= tool({ ...overrides,"),
        TOOL.replace("execute:", "execute: undefined, execute:"),
    ],
)
def test_unproven_or_mutable_exports_do_not_dispatch(index, tool):
    assert not _matches(index, {"route.ts": SOURCE, "tools.ts": tool})


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace('from "ai"', 'from "unrelated"'),
        SOURCE.replace('import { generateText } from "ai";', ""),
        SOURCE.replace("return generateText", "generateText = fake; return generateText"),
        SOURCE.replace("answer()", "answer(lookup)"),
        SOURCE.replace("answer()", "answer({lookup})"),
        SOURCE.replace("return generateText", "lookup.execute = undefined; return generateText"),
        SOURCE.replace("return generateText", "lookup['execute'] = undefined; return generateText"),
        SOURCE.replace("return generateText", "unknown(lookup); return generateText"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup}, toolChoice: 'none'"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup}, toolChoice: policy"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup}, activeTools: []"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup}, activeTools: ['other']"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup}, ...overrides"),
        SOURCE.replace("tools: {lookup}", "tools: {lookup, ...overrides}"),
        SOURCE.replace("return generateText", "if (false) return generateText"),
        SOURCE.replace("import { lookup }", "import type { lookup }"),
        SOURCE.replace("import { lookup }", "import { type lookup }"),
        SOURCE.replace("import { lookup }", "import { lookup, lookup }"),
        SOURCE.replace("import { lookup }", "import { lookup, other as }"),
        SOURCE.replace("import { lookup }", "import { missing as lookup }"),
        SOURCE.replace("./tools", "../tools"),
        SOURCE.replace("./tools", "/tools"),
        SOURCE.replace("./tools", "external/tools"),
        SOURCE.replace("./tools", "./tools.json"),
    ],
)
def test_unknown_binding_policy_and_path_stay_opaque(index, source):
    assert not _matches(index, {"route.ts": source, "tools.ts": TOOL})


@pytest.mark.parametrize("other", ["tools.js", "tools/index.ts", "tools.tsx"])
def test_ambiguous_module_candidates_rejected(index, other):
    assert not _matches(index, {"route.ts": SOURCE, "tools.ts": TOOL, other: TOOL})
    assert not _matches(index, {"route.ts": SOURCE, "tools.ts": TOOL}, observed=[other])


@pytest.mark.parametrize(
    "configuration",
    [
        '{"extends":"./base.json","compilerOptions":{"paths":{"@/*":["./*"]}}}',
        '{"references":[],"compilerOptions":{"paths":{"@/*":["./*"]}}}',
        '{"compilerOptions":{"paths":{"@/*":["./*","./src/*"]}}}',
        '{"compilerOptions":{"paths":{"@/*":["../*"]}}}',
        '{"compilerOptions":{"paths":{"@/*":["/*"]}}}',
        '{"compilerOptions":{"paths":{"@/*":["./*"],"@/tools":[]}}}',
        '{"compilerOptions":{"paths":{"@/*":["./*"],"@/tools":["./tools","./alternate"]}}}',
        '{"compilerOptions":{"paths":{"@/*":["./*"]},"paths":{"@/*":["./other/*"]}}}',
        "{malformed",
        "[]",
    ],
)
def test_unsupported_alias_configuration_rejected(index, configuration):
    files = {
        "route.ts": SOURCE.replace("./tools", "@/tools"),
        "tools.ts": TOOL,
        "tsconfig.json": configuration,
    }
    assert not _matches(index, files)


def test_nearer_or_conflicting_configuration_blocks_root_alias(index):
    files = {"lib/route.ts": SOURCE.replace("./tools", "@/tools"), "tools.ts": TOOL, "tsconfig.json": CONFIG}
    assert not _matches(index, files, source="lib/route.ts", observed=["lib/tsconfig.json"])
    files["jsconfig.json"] = CONFIG
    assert not _matches(index, files, source="lib/route.ts")


@pytest.mark.parametrize("pattern", ["ai", "a*", "*i", "*"])
def test_configuration_cannot_replace_the_ai_sdk(index, pattern):
    configuration = '{"compilerOptions":{"paths":{' + f'"{pattern}":["./mock"]' + "}}}"
    assert not _matches(index, {"route.ts": SOURCE, "tools.ts": TOOL, "tsconfig.json": configuration})


@pytest.mark.parametrize(
    "configuration",
    ['{"compilerOptions":{"baseUrl":"."}}', '{"extends":"./missing.json"}', "{malformed"],
)
def test_unknown_sdk_resolution_cannot_establish_executable_tools(index, configuration):
    assert not _matches(index, {"route.ts": SOURCE, "tools.ts": TOOL, "tsconfig.json": configuration})


def test_sdk_binding_is_checked_at_the_exporting_module(index):
    files = {
        "route.ts": SOURCE.replace("./tools", "./lib/tools"),
        "lib/tools.ts": TOOL,
        "lib/tsconfig.json": '{"compilerOptions":{"paths":{"ai":["./fake"]}}}',
    }
    assert not _matches(index, files)


def test_wildcard_substitution_precedes_parent_normalization(index):
    files = {
        "route.ts": SOURCE.replace("./tools", "@/deep/file"),
        "tools.ts": TOOL,
        "deep/tools.ts": "export const lookup = undefined;",
        "tsconfig.json": '{"compilerOptions":{"paths":{"@/*":["./*/../tools"]}}}',
    }
    assert not _matches(index, files)
    files["deep/tools.ts"] = TOOL
    assert _matches(index, files)


def test_project_boundaries_are_preserved(index):
    files = {"app/route.ts": SOURCE, "app/tools.ts": TOOL}
    assert _matches(index, files, source="app/route.ts", project="app")
    resolver = JavascriptProjectTools()
    resolver.add("other", "other/tools.ts", TOOL, ".ts")
    ignored, _ = noncode_ranges(SOURCE, "javascript", ".ts")
    assert not resolver.matches(index, "app", "app/route.ts", SOURCE, ignored)


def test_imported_evidence_requires_the_imported_tool_to_be_selected(index):
    source = SOURCE.replace(
        "tools: {lookup}",
        "tools: {lookup, other: {execute: () => 1}}, activeTools: ['other']",
    )
    assert not _matches(index, {"route.ts": source, "tools.ts": TOOL})


def test_catalog_source_and_consumer_limits_are_explicit(index, monkeypatch):
    resolver = JavascriptProjectTools()
    monkeypatch.setattr(module, "MAX_MODULES", 1)
    resolver.note_path(".", "tools.ts")
    resolver.note_path(".", "other.ts")
    resolver.add(".", "other.ts", TOOL, ".ts")
    assert resolver.full
    assert not resolver.exports
    with pytest.raises(SourceBudgetExceeded, match="module limit"):
        resolver.matches(index, ".", "route.ts", SOURCE, [])
    resolver = JavascriptProjectTools()
    monkeypatch.setattr(module, "MAX_SOURCE_BYTES", 1)
    with pytest.raises(SourceBudgetExceeded, match="source limit"):
        resolver.add(".", "tools.ts", TOOL, ".ts")
    with pytest.raises(SourceBudgetExceeded, match="consumer limit"):
        resolver.matches(index, ".", "route.ts", SOURCE, [])
    resolver = JavascriptProjectTools()
    monkeypatch.setattr(module, "MAX_CONFIG_BYTES", 1)
    with pytest.raises(SourceBudgetExceeded, match="configuration limit"):
        resolver.add(".", "tsconfig.json", CONFIG, ".json")


def test_prefilter_handles_multiline_alias_imports():
    assert has_local_tool_import(SOURCE.replace("import { lookup }", "import {\n lookup,\n}"))
    assert not has_local_tool_import("const text = 1;")


def test_unused_project_catalog_does_not_make_ordinary_scan_incomplete(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(module, "MAX_MODULES", 1)
    for name in ("first", "second", "third"):
        (tmp_path / f"{name}.ts").write_text("export const harmless = 1;")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors


@pytest.mark.parametrize("source", [SOURCE, INLINE, INLINE.replace("generateText", "streamText")])
@pytest.mark.parametrize(
    "configuration",
    [
        '{"compilerOptions":{"paths":{"ai":["./mock"]}}}',
        '{"compilerOptions":{"paths":{"*":["./mock"]}}}',
        '{"compilerOptions":{"baseUrl":"."}}',
        '{"extends":"./missing.json"}',
    ],
)
def test_filesystem_withholds_sdk_proof_when_project_can_replace_ai(
    tmp_path, run_connector, source, configuration
):
    (tmp_path / "route.ts").write_text(source)
    (tmp_path / "tools.ts").write_text(TOOL)
    (tmp_path / "tsconfig.json").write_text(configuration)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    project = next(finding for finding in findings if finding.resource_type == "project")
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in project.capabilities
    assert not any("import-bound agent construction" in evidence.description for evidence in project.evidence)


def test_filesystem_preserves_normal_inline_sdk_tools(tmp_path, run_connector):
    (tmp_path / "route.ts").write_text(INLINE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert next(finding for finding in findings if finding.resource_type == "project").kind == Kind.AGENT


@pytest.mark.parametrize("limit", ["MAX_MODULES", "MAX_PENDING_FILES"])
def test_filesystem_does_not_restore_sdk_proof_after_catalog_or_queue_limit(
    tmp_path, run_connector, monkeypatch, limit
):
    from shadowscan.connectors.code import file_scan

    monkeypatch.setattr(module if limit == "MAX_MODULES" else file_scan, limit, 0)
    (tmp_path / "route.ts").write_text(INLINE)
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"ai":["./mock"]}}}')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert ctx.stats.incomplete
    assert (
        next(finding for finding in findings if finding.resource_type == "project").kind
        == Kind.FRAMEWORK_USAGE
    )


def test_filesystem_classifies_imported_single_step_tool(tmp_path, run_connector):
    (tmp_path / "route.ts").write_text(SOURCE)
    (tmp_path / "tools.ts").write_text(TOOL)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    project = next(finding for finding in findings if finding.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert "tool-use" in project.capabilities
    assert any("resolved local executable tool" in evidence.description for evidence in project.evidence)


def test_filesystem_resolves_explicit_alias_offline_fixture(run_connector):
    path = Path(__file__).parents[1] / "fixtures/code/javascript_imported_tool"
    findings, ctx = run_connector("code.filesystem", path=str(path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    project = next(finding for finding in findings if finding.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert any("resolved local executable tool" in evidence.description for evidence in project.evidence)
