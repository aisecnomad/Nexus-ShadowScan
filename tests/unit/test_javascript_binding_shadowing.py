"""A JavaScript binding that a method parameter shadows is dropped, without rescanning the rest of the text."""

from __future__ import annotations

import random
import re
import time

import pytest
import regex

from shadowscan.connectors.code.source_semantics import (
    SourceBudgetExceeded,
    _Binding,
    _drop_uncertain_bindings,
    _javascript_declaration_names,
    _named_as_method_parameter,
)
from shadowscan.models import Kind

# The whole-source pattern that ``_named_as_method_parameter`` replaced. It defines what shadowing means.
_ORIGINAL = r"(?:^|[;{{}}\n])\s*(?:async\s+)?[\w$]+\s*\([^)]*\b{name}\b[^)]*\)\s*(?::[^{{}};]+)?\{{"


def _original(text: str, name: str, timeout: float = 5) -> bool:
    pattern = _ORIGINAL.format(name=re.escape(name))
    return bool(regex.search(pattern, text, timeout=timeout, concurrent=False))


def _windowed(text: str, name: str) -> bool:
    parentheses = [match.start() for match in re.finditer(r"\)", text)]
    terminals = [match.start() for match in re.finditer(r"[{};]", text)]
    return _named_as_method_parameter(text, re.escape(name), parentheses, terminals)


def _kept(text: str, name: str = "Name") -> bool:
    bindings = {name: _Binding("module", name)}
    _drop_uncertain_bindings(bindings, text, [])
    return name in bindings


@pytest.mark.parametrize(
    "text",
    [
        "class A {\n  async run(Name: string, y) {\n  }\n}",
        "foo(Name) {",
        "}\nfoo(a, Name): Promise<void> {\n",
        "async foo(Name) : T {",
        "if (Name) {",
        "  get(first, Name = 1) {",
    ],
)
def test_a_method_declaring_the_name_as_a_parameter_shadows_the_binding(text: str):
    assert _original(text, "Name")
    assert _windowed(text, "Name")
    assert not _kept(text)


@pytest.mark.parametrize(
    "text",
    [
        "x = foo(Name) {",  # an expression, not a statement start
        ") foo(Name) {",  # the declaration does not start a statement
        "a.b(Name) {",  # a member call
        "foo(Namex) {",
        "foo(xName) {",
        "foo(Name);",  # a call, not a declaration
        "foo(Name)",  # nothing follows the parameters
        "foo(Name) : T;",
        "run(a(b), Name)\n{",  # a ")" before the name ends the parameter list the pattern reads
    ],
)
def test_other_uses_of_the_name_keep_the_binding(text: str):
    assert not _original(text, "Name")
    assert not _windowed(text, "Name")
    assert _kept(text)


def test_windowed_check_agrees_with_the_original_pattern_on_generated_source():
    rng = random.Random(20261008)
    pieces = [
        "Name",
        "foo",
        "async ",
        "(",
        ")",
        "{",
        "}",
        ";",
        "\n",
        " ",
        ", ",
        ": T",
        "get ",
        "x.",
        "=>",
        "if ",
    ]
    matches = 0
    for _ in range(4000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 30)))
        expected = _original(text, "Name")
        matches += expected
        assert _windowed(text, "Name") == expected, text
    assert matches > 0  # the generator reaches the pattern


def test_statement_starts_that_never_close_do_not_exhaust_the_pattern_budget():
    # Twenty thousand statement starts that open a parenthesis and never close it made the original
    # pattern rescan the rest of the text from each one: it timed out at the 0.1 s pattern budget.
    text = "const client = new OpenAI();\n" + "f(\n" * 20_000
    with pytest.raises(TimeoutError):
        _original(text, "OpenAI", timeout=0.1)
    assert _kept(text, "OpenAI")


def test_a_large_typescript_file_keeps_its_analysis(tmp_path, run_connector):
    # 5,000 unclosed calls: the original check timed out here. The file's own budget is
    # raised so only that check is under test: redacting this file's excerpts is most of
    # its 2 s allowance under coverage tracing, which made the default budget flaky.
    (tmp_path / "big.ts").write_text(
        'import OpenAI from "openai";\n'
        "const client = new OpenAI();\n"
        'await client.chat.completions.create({ model: "gpt-4o", messages: [] });\n' + "f(\n" * 5_000,
        encoding="utf-8",
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_timeout=10)
    assert not [error for error in ctx.stats.errors if "TimeoutError" in error], ctx.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)


def test_windowed_check_agrees_with_the_original_pattern_on_more_generated_source():
    rng = random.Random(8101009)
    pieces = [
        "Name",
        "foo",
        "async ",
        "(",
        ")",
        "{",
        "}",
        ";",
        "\n",
        " ",
        ", ",
        ": T",
        "if ",
        "x(",
        "=> {",
        "\t",
    ]
    for _ in range(6000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 40)))
        assert _windowed(text, "Name") == _original(text, "Name"), text


_QUADRATIC_SHAPES = {
    "closing-parens": lambda: "x OpenAI ) " * 30_000 + "{",
    "or-chain": lambda: "if (" + "isOk(OpenAI) || " * 20_000 + "z) {",
    "then-chain": lambda: "p" + ".then(OpenAI)" * 20_000 + ".then(function () {\n})",
}


@pytest.mark.parametrize("shape", sorted(_QUADRATIC_SHAPES))
def test_the_quadratic_shapes_found_in_review_stay_fast(shape: str):
    source = _QUADRATIC_SHAPES[shape]()
    started = time.perf_counter()
    _kept(source, "OpenAI")
    assert time.perf_counter() - started < 2.0


def test_windowed_check_agrees_with_the_original_pattern_on_declaration_shaped_source():
    # The unstructured generator rarely forms a declaration; this one does about half the time.
    rng = random.Random(99)
    heads = ["foo(", "async foo(", "\nbar(", ";baz(", "{ qux(", "} run(", "if (", "x.y(", "a = b(", "get("]
    mids = ["Name", "a, Name", "Name = 1", "a(b), Name", "x, Name, y", "Namex", "(Name)", "{ Name }", "", " "]
    tails = [")", " ) {", ") : T {", ") {", "); ", ")\n{", ") => {", "): Promise<void> {", ") ;", "))"]
    seams = ["", "\n", " ", "x;", "}"]
    matches = 0
    for _ in range(3000):
        text = "".join(
            rng.choice(heads) + rng.choice(mids) + rng.choice(tails) + rng.choice(seams)
            for _ in range(rng.randint(1, 4))
        )
        expected = _original(text, "Name")
        matches += expected
        assert _windowed(text, "Name") == expected, text
    assert matches > 500


def _project(tmp_path, run_connector, declaration, suffix=".ts"):
    (tmp_path / f"app{suffix}").write_text(
        "import { Agent } from '@openai/agents';\n"
        "class LocalAgent {}\n"
        "export function create() {\n"
        f"  {declaration}\n"
        "  return new Agent({name: 'worker', instructions: 'Help'});\n"
        "}\n"
    )
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False
    )
    assert not context.stats.incomplete, context.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize("suffix", [".js", ".ts", ".tsx"])
@pytest.mark.parametrize(
    "declaration",
    [
        "const Agent = LocalAgent;",
        "let first, Agent;",
        "let Agent\n",
        "function inner() { var Agent }",
        "var first, Agent;",
        "const { Agent } = { Agent: LocalAgent };",
        "const [Agent] = [LocalAgent];",
        "let { factory: Agent } = factories;",
        "var { outer: { factory: Agent } } = factories;",
        "const { outer: [Agent] } = factories;",
        "const [first, , { factory: Agent }] = factories;",
        "const { ...Agent } = factories;",
        "const [first, ...Agent] = factories;",
        "const [...[Agent]] = factories;",
        "const { Agent = LocalAgent } = factories;",
        "const { factory: Agent = LocalAgent } = factories;",
        "const [Agent = LocalAgent] = factories;",
        "const first = 1, { Agent } = factories;",
        "let first, [Agent] = factories;",
        "const first = call({ nested: [1, 2] }), { Agent } = factories;",
        "const first = 1, { outer: [Agent = LocalAgent] } = factories;",
        "const { [key]: Agent } = factories;",
        "const { 'factory': Agent } = factories;",
        "for (const { Agent } of factories) { new Agent(); }",
    ],
)
def test_declaration_binding_names_shadow_imports(tmp_path, run_connector, declaration, suffix):
    project = _project(tmp_path, run_connector, declaration, suffix)
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert not any("import-bound agent construction" in item.description for item in project.evidence)


@pytest.mark.parametrize(
    "declaration",
    [
        "",  # actual SDK construction remains detected
        "const { Agent: local } = factories;",
        "const { outer: { Agent: local } } = factories;",
        "const { other = Agent } = factories;",
        "const { other = choose(Agent) } = factories;",
        "const { other: local = Agent } = factories;",
        "const [local = Agent] = factories;",
        "const { [Agent.name]: local } = factories;",
        "const { [choose(Agent)]: local } = factories;",
        "const { 'Agent': local } = factories;",
        "const other = { Agent: LocalAgent };",
        "const other = [Agent];",
        "const first = choose(Agent), { other = Agent } = factories;",
        "const other = { const: Agent, let: Agent, var: Agent };",
        "const other = object.const(Agent);",
        "const options = { first: 1, [Agent.name]: true };",
        "const options = { first: 1, [Agent]: true };",
        "const { other = { first: 1, [Agent.name]: true } } = values;",
        "const other = (first, [Agent] in options);",
        "const other = (first, { Agent } in options);",
        "function f<const Agent>() {}",
        "const other = <T, const Agent extends object>(value: T) => value;",
        "const other = <T, const Agent, U>(value: T) => value;",
        "let other = use(value, Agent\n);",
        "let other: Pair<First, Agent\n> = value;",
        "class C { const = 1; }",
        "interface C { let?: string; }",
        "class C { var!: string; }",
        "class C { const<T>() {} }",
        "const other = choose<Deps, Agent>();",
        "const other = choose<Deps, Agent>;",
        "const { other = choose<Deps, Agent>() } = factories;",
        "const other = <const T, const Agent>(value: T) => value;",
        "const π = 3.14;",
        "const πvalue = 3.14;",
        "const { other: πvalue } = factories;",
        "const other = { constructor: Agent } as const;",
        "const { other = () => { const local = Agent; return local; } } = factories;",
        # A member named like a declaration keyword is a read, not a new declaration.
        "const { other = factories.const } = factories;",
        "const { other = factories?.let, more = factories.var } = factories;",
        "const { other = factories\n    .const } = factories;",
    ],
)
def test_property_keys_and_initializer_reads_do_not_shadow_imports(tmp_path, run_connector, declaration):
    project = _project(tmp_path, run_connector, declaration)
    assert project.kind == Kind.AGENT
    assert any("import-bound agent construction" in item.description for item in project.evidence)


@pytest.mark.parametrize(
    "declaration",
    [
        "const { Agent }: { Agent: typeof LocalAgent } = factories;",
        "const first: Map<string, number> = values, { Agent } = factories;",
        "let first: [string, number], [Agent] = factories;",
        "let first!: string, { Agent } = factories;",
        "let first, { Agent }: Options = factories;",
        "let first, [Agent]: Options = factories;",
        "const fs = require('fs'), [Agent]: Options = factories;",
        "const first = {} as const, { Agent } = factories;",
        "const first = choose<Deps, Result>(), { Agent } = factories;",
        "const { first = factories.const } = factories, { Agent } = more;",
        "const first = left < right, { Agent } = factories;",
        "let first = left < right, Agent = LocalAgent > value;",
        "let first = left < right, Agent\nother > (value);",
        "const πvalue = 1, { Agent } = factories;",
    ],
)
def test_typescript_annotations_preserve_declaration_lists(tmp_path, run_connector, declaration):
    assert _project(tmp_path, run_connector, declaration).kind == Kind.FRAMEWORK_USAGE


@pytest.mark.parametrize(
    "declaration",
    [
        "const { other }: { Agent: typeof LocalAgent } = factories;",
        "const other: Map<string, Agent> = values;",
        "const other: [string, Agent] = values;",
        "const other: Factory<() => void, Agent> = values;",
    ],
)
def test_typescript_type_references_do_not_shadow_imports(tmp_path, run_connector, declaration):
    assert _project(tmp_path, run_connector, declaration).kind == Kind.AGENT


@pytest.mark.parametrize(
    "source", ["const { Agent: } = x;", "const [Agent", "const { ...other, Agent } = x;"]
)
def test_malformed_binding_patterns_cannot_establish_import_proof(source):
    from shadowscan.connectors.code.source_semantics import _Binding, _drop_uncertain_bindings

    bindings = {"Agent": _Binding("@openai/agents", "Agent")}
    _drop_uncertain_bindings(bindings, source, [])
    assert bindings == {}


def test_binding_pattern_depth_is_bounded():
    source = "const " + "[" * 130 + "Agent" + "]" * 130 + " = values;"
    from shadowscan.connectors.code.source_semantics import _Binding, _drop_uncertain_bindings

    with pytest.raises(SourceBudgetExceeded, match="pattern nesting"):
        _drop_uncertain_bindings({"Agent": _Binding("@openai/agents", "Agent")}, source, [])


def test_many_declarations_are_read_without_rescanning_initializers():
    # Thousands of declarations and references must not become thousands of
    # whole-file scans or mistake expression names for declared names.
    source = "\n".join(f"const {{ other{number} = use(Agent) }} = factories;" for number in range(2000))
    names = _javascript_declaration_names(source, source, [], {"Agent"})
    assert len(names) == 2000
    assert "Agent" not in names


def test_review_fixture_keeps_local_constructions_as_framework_usage(fixtures, run_connector):
    findings, context = run_connector(
        "code.filesystem",
        path=str(fixtures / "js_review_binding_shadowing"),
        scan_secrets=False,
        use_git=False,
    )
    assert not context.stats.incomplete, context.stats.errors
    project = next(finding for finding in findings if finding.resource_type == "project")
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert not any("import-bound agent construction" in item.description for item in project.evidence)


def test_ordinary_declaration_bulk_and_comma_object_arguments_stay_complete(tmp_path, run_connector):
    # The comma followed by an object is an initializer argument, not another
    # declarator. It must not charge the rest of the file to a token cap.
    declarations = "const options = use(value, { OpenAI });\n" + "".join(
        f"const value{number} = compute({number}, other{number});\n" for number in range(6000)
    )
    (tmp_path / "app.ts").write_text(
        'import OpenAI from "openai";\n' + declarations + "const client = new OpenAI();\n"
    )
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False
    )
    assert not context.stats.incomplete, context.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)


@pytest.mark.parametrize("prefix", ["", "const { unrelated } = options;\n"])
def test_require_binding_keeps_later_partial_call_diagnostics(index, prefix):
    from shadowscan.connectors.code.source_ranges import noncode_ranges
    from shadowscan.connectors.code.source_semantics import bound_source_matches

    source = "const { Agent } = require('@openai/agents');\n" + prefix + "const client = new Agent(\n"
    ignored, _ = noncode_ranges(source, "javascript")
    truncated = []
    bound_source_matches(index, source, "javascript", ignored, truncated=truncated)
    assert truncated == [source.count("\n")]


@pytest.mark.parametrize("wrapped", [False, True])
def test_unrelated_asi_and_arrow_body_declarations_keep_sdk_evidence(tmp_path, run_connector, wrapped):
    source = 'import OpenAI from "openai";\n'
    if wrapped:
        source += "const handler = () => {\nconst { other } = factories;\n"
        source += "".join(
            f"const value{number} = compute({number}, other{number});\n" for number in range(6000)
        )
        source += "};\n"
    else:
        source += "const { other } = factories\n"
        source += "".join(
            f"const value{number} = compute({number}, other{number})\n" for number in range(6000)
        )
    source += "const client = new OpenAI();\n"
    (tmp_path / "app.ts").write_text(source)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False
    )
    assert not context.stats.incomplete, context.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)
