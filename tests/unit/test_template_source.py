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

from shadowscan.connectors.code.template_source import unrendered_template
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
