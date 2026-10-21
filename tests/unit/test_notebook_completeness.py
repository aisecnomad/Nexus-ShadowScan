"""Notebooks that left run-llama/llama_index incomplete: IPython syntax, outputs and broken cells.

A default scan of llama_index exited 3 on 40 notebook and data-file diagnostics:
magics IPython accepts but the scanner did not (``% pip install``, a magic
continued with a backslash, ``files = !ls``, ``%%ngql``), notebooks whose saved
outputs are megabytes of base64 images, tutorial cells holding placeholders
(``api_key = <YOUR API KEY>``), and a module mapping whose own package name
carries a model vendor's stem (``llama_index.core``).
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest

from shadowscan.connectors.code.model_identifiers import MAX_MODEL_LITERALS_PER_FILE
from shadowscan.connectors.code.source_text import _without_ipython_lines
from shadowscan.models import Kind
from shadowscan.utils.text import notebook_to_source, notebook_without_binary_data

AGENT_CELL = (
    "from langchain.agents import AgentExecutor, create_tool_calling_agent\n"
    "from langchain_openai import ChatOpenAI\n"
    "agent = create_tool_calling_agent(ChatOpenAI(), [], prompt)\n"
    "executor = AgentExecutor(agent=agent, tools=[])\n"
)
# A credential-shaped value in a text output: the outputs are read only for credentials.
LEAKED = "OPENAI_API_KEY=sk-proj-" + "Q7v2Lm9Xr4Tz8Kp1Wn6Ys3Bd5Hf0Jc2Ge7Ua4Ri9Oe1Nl6Mq3Vt8Zx5Cw2Pb7Sd4"
IMAGE = "iVBORw0KGgo" + "A" * 6_000


def _cell(source: str, outputs: list[dict] | None = None) -> dict:
    return {
        "cell_type": "code",
        "source": [source],
        "metadata": {},
        "outputs": outputs or [],
        "execution_count": 1,
    }


def _notebook(*cells: dict) -> str:
    return json.dumps({"cells": list(cells), "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1)


def _without_binary(document: str) -> tuple[str, int]:
    binary: list[str] = []
    notebook_to_source(document, binary=binary)
    return notebook_without_binary_data(document, binary)


def _project(root: Path, files: dict[str, str]) -> Path:
    """61 ordinary files, so a gap of one entry is within the default 2% budget."""
    for i in range(60):
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "src" / f"m{i}.py").write_text(f"x = {i}\n")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


# ----------------------------------------------------------------- IPython syntax


@pytest.mark.parametrize(
    "setup",
    [
        "% pip install llama-index-llms-groq\n",
        "% autoreload 2\n",
        "%pip install --upgrade \\\n    openinference-instrumentation-llama-index \\\n    arize-phoenix\n",
        "!pip install a \\\n  b\n",
        "files = !ls data\nnames = %who_ls\n",
        "for path in paths:\n    size = ! du -sh {path}\n",
    ],
    ids=[
        "spaced-pip",
        "spaced-autoreload",
        "continued-magic",
        "continued-shell",
        "assigned",
        "indented-assigned",
    ],
)
def test_ipython_syntax_llama_index_uses_keeps_the_import_binder(tmp_path, run_connector, setup):
    (tmp_path / "demo.ipynb").write_text(_notebook(_cell(setup), _cell(AGENT_CELL)))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize(
    "line",
    [
        'greeting = ("Hello %s"\n            % name)\n',  # a continued modulo is not a magic
        "x = a % b\n",
        "y = x != z\n",
        "pip in installed\n",
        "ratio = total % size\n",
        # Black splits a long modulo before its operator: inside brackets, or after a
        # backslash, "% name" continues an expression (IPython reads an escape only at
        # the start of a logical line), whatever the name.
        "label = (\n    '%.3f'\n    % precision\n)\n",
        "elapsed = (\n    start\n    % time.time()\n)\n",
        "rows = [\n    '%s' %\n    x for x in xs\n]\n",
        "label = '%s' \\\n    % pip\n",
        "call(\n    a,\n    %matplotlib\n)\n",
    ],
)
def test_python_lines_are_left_as_they_are(line):
    assert _without_ipython_lines(line) == line


def test_a_magic_after_a_closed_bracket_is_still_masked():
    cell = "values = (1,\n          2)\n% pip install openai\n"
    assert _without_ipython_lines(cell).splitlines()[-1].strip() == "0"


@pytest.mark.parametrize(
    ("line", "masked"),
    [
        (
            "% time executor = AgentExecutor(agent=agent, tools=[])\n",
            "0;     executor = AgentExecutor(agent=agent, tools=[])\n",
        ),
        ("%timeit run(agent)\n", "0;      run(agent)\n"),
        ("result = %prun agent.invoke(x)\n", "result = 0;    agent.invoke(x)\n"),
        ("%timeit -n 10 run(agent)\n", "0" + " " * 23 + "\n"),  # options: the whole line, as before
    ],
)
def test_a_timing_magic_keeps_the_statement_it_runs(line, masked):
    assert _without_ipython_lines(line) == masked


def test_a_timed_statement_is_bound_like_the_plain_one(tmp_path, run_connector):
    evidence = {}
    for name, cell in (
        ("plain", AGENT_CELL),
        ("timed", AGENT_CELL.replace("executor = ", "% time executor = ")),
    ):
        (tmp_path / name).mkdir()
        (tmp_path / name / "demo.ipynb").write_text(_notebook(_cell(cell)))
        findings, ctx = run_connector("code.filesystem", path=str(tmp_path / name), use_git=False)
        assert not ctx.stats.warnings and not ctx.stats.errors
        evidence[name] = sorted(
            (e.signal, e.weight)
            for finding in findings
            if finding.kind == Kind.AGENT
            for e in finding.evidence
        )
    assert evidence["timed"] and evidence["timed"] == evidence["plain"]


def test_a_rewritten_magic_keeps_every_offset_and_line():
    cell = "%pip install a \\\n  b \\\n  c\nimport os\n"
    out = _without_ipython_lines(cell)
    assert len(out) == len(cell) and out.count("\n") == cell.count("\n")
    assert out.splitlines()[-1] == "import os"


def test_a_graph_query_cell_magic_is_not_python(tmp_path, run_connector):
    query = (
        "%%ngql\nUSE paul_graham_essay;\nMATCH (p:`entity`)-[e:relationship]->(m) RETURN p, e, m LIMIT 10;\n"
    )
    (tmp_path / "graph.ipynb").write_text(_notebook(_cell(query), _cell(AGENT_CELL)))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors


# ---------------------------------------------------------- outputs of large notebooks


def test_binary_output_data_is_emptied_and_every_line_keeps_its_number():
    document = _notebook(
        _cell(
            "plot()\n",
            [
                {
                    "output_type": "display_data",
                    "metadata": {},
                    "data": {
                        "image/png": IMAGE,
                        "image/jpeg": [IMAGE[:100], IMAGE[100:200]],
                        "image/svg+xml": "<svg><text>kept</text></svg>",
                        "text/plain": ["<Figure size 640x480 with 1 Axes>"],
                    },
                }
            ],
        ),
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": ["![x](attachment:a.png)"],
            "attachments": {"a.png": {"image/png": IMAGE}},
        },
    )
    out, removed = _without_binary(document)
    assert out.count("\n") == document.count("\n")
    assert removed == 2 * len(IMAGE) + 200
    parsed = json.loads(out)
    data = parsed["cells"][0]["outputs"][0]["data"]
    assert data["image/png"] == "" and data["image/jpeg"] == ["", ""]
    assert data["image/svg+xml"] == "<svg><text>kept</text></svg>"
    assert data["text/plain"] == ["<Figure size 640x480 with 1 Axes>"]
    assert parsed["cells"][1]["attachments"]["a.png"]["image/png"] == ""


def test_only_base64_binary_in_output_bundles_and_attachments_is_emptied():
    text_as_base64 = base64.b64encode(LEAKED.encode()).decode()
    document = _notebook(
        {
            **_cell(
                "plot()\n",
                [
                    {
                        "output_type": "display_data",
                        "metadata": {"image/png": LEAKED},  # metadata holds ordinary data
                        "data": {
                            "image/png": LEAKED,  # not base64
                            "image/gif": text_as_base64,  # base64, but of text
                            "application/pdf": "JVBERi0" + "x-y_z" * 40,  # not strict base64
                            "image/jpeg": IMAGE,
                        },
                    }
                ],
            ),
            "metadata": {"image/png": "iVBORw0KGgo" + "B" * 600},
        },
    )
    out, removed = _without_binary(document)
    assert removed == len(IMAGE)
    parsed = json.loads(out)
    data = parsed["cells"][0]["outputs"][0]["data"]
    assert data["image/png"] == LEAKED and data["image/gif"] == text_as_base64
    assert data["application/pdf"].startswith("JVBERi0") and data["image/jpeg"] == ""
    assert parsed["cells"][0]["outputs"][0]["metadata"] == {"image/png": LEAKED}
    assert parsed["cells"][0]["metadata"] == {"image/png": "iVBORw0KGgo" + "B" * 600}


@pytest.mark.parametrize("where", ["data", "metadata", "pdf"])
def test_a_credential_under_a_binary_mime_key_is_still_read(tmp_path, run_connector, where):
    # Emptying went by the key's name: plaintext under "image/png" anywhere was not read.
    output: dict = {"output_type": "display_data", "metadata": {}, "data": {"image/png": IMAGE}}
    if where == "data":
        output["data"]["image/jpeg"] = LEAKED
    elif where == "metadata":
        output["metadata"] = {"image/png": LEAKED}
    else:
        output["data"]["application/pdf"] = LEAKED
    _project(tmp_path, {"docs/plot.ipynb": _notebook(_cell("show()\n", [output]), _cell(AGENT_CELL))})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=5_000)
    secrets = [finding for finding in findings if finding.kind == Kind.SECRET]
    assert secrets and secrets[0].resource.endswith("docs/plot.ipynb")
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)


def test_an_oversize_notebook_that_does_not_parse_stays_an_oversize_gap(tmp_path, run_connector):
    # A stray bracket used to raise IndexError in the output view: reason "other".
    output = {"output_type": "display_data", "metadata": {}, "data": {"image/png": IMAGE}}
    broken = _notebook(_cell("show()\n", [output]), _cell(AGENT_CELL)) + "]"
    (tmp_path / "plot.ipynb").write_text(broken)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=5_000)
    assert ctx.stats.incomplete
    reasons = {gap["reason"] for gap in ctx.stats.coverage["details"]}
    assert reasons and reasons <= {"oversize-file", "unparsed-input"}, reasons


def test_the_output_view_of_a_large_notebook_is_linear(tmp_path):
    outputs = [{"output_type": "display_data", "metadata": {}, "data": {"image/png": IMAGE}}] * 2_500
    document = _notebook(_cell("show()\n", outputs))  # 15 MB of images
    started = time.perf_counter()
    out, removed = _without_binary(document)
    assert time.perf_counter() - started < 3.0
    assert removed == 2_500 * len(IMAGE) and len(out) < len(document) // 50


def test_escaped_binary_spellings_stop_the_rebuild_quickly():
    # No writer escapes base64, but a hostile notebook can spell every value
    # with an escape, so its JSON encoding is never found and each miss scans
    # to the document's end. The rebuild stops after a few misses; the
    # notebook keeps its oversize gap and nothing of it goes unread.
    outputs = [{"output_type": "display_data", "metadata": {}, "data": {"image/png": IMAGE}}] * 2_500
    document = _notebook(_cell("show()\n", outputs)).replace('"iVBOR', '"\\u0069VBOR')
    started = time.perf_counter()
    out, removed = _without_binary(document)
    assert time.perf_counter() - started < 3.0
    assert removed == 0 and out == document


def test_a_large_notebook_of_images_is_read_in_full_for_credentials(tmp_path, run_connector):
    # Megabytes of rendered figures used to leave the outputs unread: exit 3.
    outputs = [
        {
            "output_type": "display_data",
            "metadata": {},
            "data": {"image/png": IMAGE, "text/plain": ["<Figure>"]},
        },
        {"output_type": "stream", "name": "stdout", "text": [LEAKED + "\n"]},
    ]
    notebook = _notebook(_cell("show()\n", outputs), _cell(AGENT_CELL))
    _project(tmp_path, {"docs/multi_modal.ipynb": notebook})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=5_000)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert not (ctx.stats.coverage or {}).get("details")
    secrets = [finding for finding in findings if finding.kind == Kind.SECRET]
    assert secrets and secrets[0].resource.endswith("docs/multi_modal.ipynb")
    assert any(
        "base64 image, audio, video and PDF output data not read" in note for note in ctx.stats.warnings
    )


def test_text_outputs_over_the_limit_are_one_budgeted_gap(tmp_path, run_connector):
    outputs = [{"output_type": "execute_result", "metadata": {}, "data": {"text/plain": ["y" * 6_000]}}]
    _project(tmp_path, {"docs/dump.ipynb": _notebook(_cell("df\n", outputs), _cell(AGENT_CELL))})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=5_000)
    assert not ctx.stats.incomplete
    assert [(gap["path"], gap["kind"]) for gap in ctx.stats.coverage["details"]] == [
        ("docs/dump.ipynb", "partial")
    ]
    _, strict = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, max_file_size=5_000, strict_coverage=True
    )
    assert strict.stats.incomplete


# ------------------------------------------------------------- cells that do not parse


def test_a_tutorial_cell_with_a_placeholder_is_one_budgeted_gap(tmp_path, run_connector):
    notebook = _notebook(_cell("api_key = <YOUR API KEY>\n"), _cell(AGENT_CELL))
    _project(tmp_path, {"docs/examples/ai21.ipynb": notebook})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert [(gap["path"], gap["kind"], gap["reason"]) for gap in ctx.stats.coverage["details"]] == [
        ("docs/examples/ai21.ipynb", "partial", "unparsed-input")
    ]
    assert any(finding.kind == Kind.AGENT for finding in findings)  # the other cell was bound


@pytest.mark.parametrize(
    "other",
    ["", "# Setup\n", "%pip install openai\n", "%%bash\necho hi\n", '"""Notes."""\n'],
    ids=["blank", "comment", "magic", "foreign", "docstring"],
)
def test_a_broken_cell_beside_cells_without_code_stays_a_gap(tmp_path, run_connector, other):
    # Only parsed Python cells that hold a statement were "the other cells analyzed".
    notebook = _notebook(_cell("client = OpenAI(api_key=<YOUR KEY>)\n"), _cell(other))
    _project(tmp_path, {"docs/examples/openai.ipynb": notebook})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_a_notebook_none_of_whose_cells_parse_stays_a_gap(tmp_path, run_connector):
    notebook = _notebook(_cell("api_key = <YOUR API KEY>\n"), _cell("source_df = <FILL-IN>\n"))
    _project(tmp_path, {"docs/examples/template.ipynb": notebook})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_strict_accounting_keeps_a_broken_cell_a_gap(tmp_path, run_connector):
    _project(tmp_path, {"docs/examples/ai21.ipynb": _notebook(_cell("api_key = <KEY>\n"), _cell(AGENT_CELL))})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=True)
    assert ctx.stats.incomplete


def test_a_tree_of_broken_notebooks_exhausts_the_budget(tmp_path, run_connector):
    for i in range(3):
        (tmp_path / f"n{i}.ipynb").write_text(_notebook(_cell("x = <FILL-IN>\n"), _cell("y = 1\n")))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and not ctx.stats.coverage["within_budget"]


# ------------------------------------------------------------------ model literals


def test_repeated_module_names_with_a_vendor_stem_do_not_reach_the_literal_bound(tmp_path, run_connector):
    # llama_index's command_line/mappings.json: 1,111 candidates, 580 of them distinct.
    mapping = {f"Class{n}": f"llama_index.core.module{n % 580}" for n in range(1_111)}
    (tmp_path / "mappings.json").write_text(json.dumps(mapping, indent=2))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.warnings


def test_distinct_model_literals_past_the_bound_are_still_disclosed(tmp_path, run_connector):
    source = "\n".join(f'x{n} = "claude-3-5-sonnet-{n:08d}"' for n in range(MAX_MODEL_LITERALS_PER_FILE + 1))
    (tmp_path / "models.py").write_text(source + "\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("distinct literals only" in diagnostic for diagnostic in ctx.stats.warnings + ctx.stats.errors)
