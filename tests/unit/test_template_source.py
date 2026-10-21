"""Unrendered template source that left crewAIInc/crewAI incomplete.

crewAI ships the project templates ``crewai create`` renders under ordinary
names: ``templates/crew/crew.py`` declares ``class {{crew_name}}():`` and its
``pyproject.toml`` a ``{{folder_name}} = ...`` key, so neither parses as
written. A file that parses once its placeholders are filled in is charged to
the coverage budget; one broken past them, strict accounting and a tree of
templates still fail the scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.code.template_source import rendered_template, unrendered_template
from shadowscan.models import Kind

CREW = (
    "from crewai import Agent, Crew, Process, Task\n"
    "from crewai.project import CrewBase, agent, crew\n\n"
    "@CrewBase\n"
    "class {{crew_name}}():\n"
    '    """{{crew_name}} crew"""\n\n'
    "    @agent\n"
    "    def researcher(self) -> Agent:\n"
    "        return Agent(config=self.agents_config['researcher'])\n"
)
PYPROJECT = (
    '[project]\nname = "{{folder_name}}"\nversion = "0.1.0"\n'
    'dependencies = ["crewai[tools]>=0.80.0"]\n\n'
    '[project.scripts]\n{{folder_name}} = "{{folder_name}}.main:run"\n'
)


def _project(root: Path, files: dict[str, str]) -> Path:
    """121 ordinary files, so gaps of two entries are within the default 2% budget."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    for i in range(120):
        (root / "src" / f"m{i}.py").write_text(f"x = {i}\n")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _gaps(ctx) -> list[tuple[str, str, str]]:
    return [
        (gap["path"], gap["kind"], gap["reason"]) for gap in (ctx.stats.coverage or {}).get("details", [])
    ]


# ------------------------------------------------------------ crewAI templates


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("templates/crew/crew.py", CREW),
        ("templates/crew/pyproject.toml", PYPROJECT),
        ("templates/flow/main.py", "{% if flow %}\nimport os\n{% endif %}\nprint({{value}})\n"),
        ("templates/data.json", '{"count": {{count}}}'),
    ],
)
def test_template_placeholders_are_recognized(rel, text):
    assert unrendered_template(rel, text)


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("templates/crew/crew.py", "class {{crew_name}}(:\n"),  # broken past its placeholders
        ("templates/crew/crew.py", "def f(:\n"),  # no placeholder at all
        ("templates/crew/crew.py", "x = '{{name}}'\n"),  # parses as written
        ("templates/crew/README.md", "{{name}}\n"),  # a format not judged
    ],
)
def test_other_files_are_not_templates(rel, text):
    assert not unrendered_template(rel, text)


def test_crewai_templates_under_ordinary_names_are_budgeted(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": CREW, "templates/crew/pyproject.toml": PYPROJECT})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert sorted(_gaps(ctx)) == [
        ("templates/crew/crew.py", "partial", "unparsed-input"),
        ("templates/crew/pyproject.toml", "partial", "unparsed-input"),
    ]
    assert any("parses once its placeholders are filled in" in w for w in ctx.stats.warnings)
    assert any(finding.kind == Kind.AGENT or "framework.crewai" in finding.frameworks for finding in findings)


def test_broken_source_beside_a_placeholder_still_fails(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": "class {{crew_name}}(:\n    pass\n"})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_strict_accounting_keeps_a_content_template_a_gap(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": CREW})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=True)
    assert ctx.stats.incomplete


def test_a_tree_of_templates_exhausts_the_budget(tmp_path, run_connector):
    for i in range(3):
        (tmp_path / f"t{i}.py").write_text(CREW)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and not ctx.stats.coverage["within_budget"]


# ------------------------------------------------------- review follow-ups


def test_an_integrity_failure_under_a_template_named_directory_still_fails(tmp_path, run_connector):
    # A repeated key is no unrendered template: the directory name explains parse failures only.
    duplicate = "model: gpt-4o\napi_base: https://api.openai.com\nmodel: x\n"
    _project(tmp_path, {"deploy/${env}/llm.yaml": duplicate})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_a_templated_manifest_keeps_its_dependency_findings(tmp_path, run_connector):
    # A placeholder must not hide the dependencies around it: the rendering is analyzed.
    manifest = (
        '[project]\nname = "svc"\nversion = "0.1"\n'
        'dependencies = ["langchain-openai", "openai", "mcp"]\n[tool.x]\n{{ x }} = 1\n'
    )
    _project(tmp_path, {"svc/pyproject.toml": manifest})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert [gap for gap in _gaps(ctx) if gap[0] == "svc/pyproject.toml"]  # still a recorded gap
    assert any("langchain" in framework for finding in findings for framework in finding.frameworks), [
        finding.title for finding in findings
    ]


def test_a_templated_module_is_bound_from_its_rendering(tmp_path, run_connector):
    # Bound from its rendering, the crew's Agent(...) construction proves an agent;
    # left unbound it was framework usage only.
    _project(tmp_path, {"templates/crew/crew.py": CREW})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert any(e.location == "templates/crew/crew.py:10" for f in agents for e in f.evidence), [
        (f.kind, f.title) for f in findings
    ]


# ------------------------------------------------- spans that cross structure


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        # A tag span from one string to another swallowed the dependencies (and a JSON5 comma).
        ("package.json", '{"name": "{%", "dependencies": {"openai": "^4",}, "x": "%}"}'),
        ("package.json", '{"name": "{{", "deps": ["openai",], "x": "}}"}'),
        ("package.json", '{"name": "{% raw %}", "dependencies": {"openai": "^4",}, "x": "{% endraw %}"}'),
        # So did a placeholder span.
        ("package.json", '{"name": "{{ a", "dependencies": {"openai": "^4",}, "x": "b }}"}'),
        ("pyproject.toml", '[project]\nname = "{{ a", dependencies = ["openai",], x = "b }}"\n'),
        # A placeholder may not hide a statement.
        ("app.py", "x = {{ 0; import openai }}\ndef f(:\n"),
        # A tag must be a line of its own, with no other tag on it.
        ("app.py", "{% if a %}import openai{% endif %}\ndef f(:\n"),
    ],
)
def test_a_span_across_strings_or_structure_is_not_a_template(rel, text):
    assert not unrendered_template(rel, text)


def test_a_manifest_hidden_inside_a_tag_span_still_fails(tmp_path, run_connector):
    manifest = '{"name": "{%", "dependencies": {"openai": "^4",}, "x": "%}"}\n'
    _project(tmp_path, {"package.json": manifest})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


@pytest.mark.parametrize("directory", ["deploy/${env}", "{{cookiecutter.slug}}"])
def test_broken_source_without_template_syntax_under_a_template_directory_still_fails(
    tmp_path, run_connector, directory
):
    # Newer Python syntax is broken source, not a template, wherever it lies.
    _project(
        tmp_path,
        {f"{directory}/app.py": "type Point = tuple[float, float]\ndef f[T](x: T) -> T: return x\nx = (\n"},
    )
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_a_template_under_a_jinja_directory_is_still_budgeted(tmp_path, run_connector):
    pyproject = '[project]\nname = "{{ cookiecutter.package_name }}"\n{%- if cookiecutter.core %}\nx = [\n{%- endif %}\n'
    _project(tmp_path, {"{{cookiecutter.package_name}}/pyproject.toml": pyproject})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert _gaps(ctx) == [("{{cookiecutter.package_name}}/pyproject.toml", "partial", "unparsed-input")]


# ------------------------------------------------- integration review follow-ups

TOOL_MODULE = (
    "import subprocess\n"
    "from agents import Agent, function_tool\n\n"
    "class {{crew_name}}():\n"
    "    pass\n\n"
    "@function_tool\n"
    "def shell(cmd: str) -> str:\n"
    "    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n\n"
    'agent = Agent(name="ops", instructions="run commands", tools=[shell])\n'
)


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("templates/crew/crew.py", CREW),
        ("templates/crew/pyproject.toml", PYPROJECT),
        ("templates/data.json", '{"count": {{count}}}'),
        ("templates/tool.py", TOOL_MODULE),
        ("templates/flow/main.py", "{% if flow %}\nimport os\n{% endif %}\nprint({{value}})\n"),
        ("templates/crlf.py", "{% if x %}\r\nclass {{crew_name}}():\r\n    pass\r\n{% endif %}\r\n"),
    ],
)
def test_a_rendering_keeps_every_line_and_character_offset(rel, text):
    # The binder's spans in the rendering locate the file's own lexical matches.
    rendered = rendered_template(rel, text)
    assert rendered is not None and len(rendered) == len(text)
    assert [len(line) for line in rendered.split("\n")] == [len(line) for line in text.split("\n")]


def test_a_bare_carriage_return_ends_a_placeholder_or_a_tag():
    # Python ends a line at a bare CR, so a placeholder spanning one could hide a statement.
    assert not unrendered_template("app.py", "x = {{ 0\rimport openai\r0 }}\n")
    assert not unrendered_template("app.py", "{% if a\rimport openai %}\nx = 1\n")


def test_a_templated_tool_keeps_its_capabilities(tmp_path, run_connector):
    # A placeholder or tag line of another length than its stand-in shifted every later
    # offset, so the shell tool's code execution was no longer within the registered tool.
    _project(tmp_path, {"templates/agent/agent.py": TOOL_MODULE})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert any("code-exec" in f.capabilities for f in agents), [(f.kind, f.capabilities) for f in findings]


def test_an_analysis_limit_on_a_rendering_fails_the_scan(tmp_path, run_connector):
    # The rendering parsed, so a binder limit is no template gap: it fails as for any source.
    weights = "WEIGHTS = [\n" + "    0.5,\n" * 1200 + "]\n"
    _project(tmp_path, {"templates/crew/crew.py": CREW + weights})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_ast_nodes=1000)
    assert ctx.stats.incomplete
    assert any("template rendering skipped" in error for error in ctx.stats.errors), ctx.stats.errors


def test_python_under_a_jinja_directory_is_a_template_only_by_its_content(tmp_path, run_connector):
    # Python runs a module under such a directory as written, and a newer interpreter
    # parses grammar this one cannot: '{{ }}' in a prompt string explains nothing.
    module = 'PROMPT = "Answer the question: {{ question }}"\nfrom agents import Agent\nx = (\n'
    _project(tmp_path, {"{{cookiecutter.agent}}/agent.py": module})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    rendered_module = "from crewai import Agent\n\nclass {{crew_name}}():\n    pass\n"
    _project(tmp_path / "ok", {"{{cookiecutter.agent}}/crew.py": rendered_module})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path / "ok"), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
