"""Provider loops retain SDK provenance through a proven call-site parameter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.models import Kind

ANNOTATED = """from openai import OpenAI as Client
import json

def ask(client: Client, question):
    messages = [{"role": "user", "content": question}]
    for turn in range(8):
        response = client.chat.completions.create(model="example", messages=messages, tools=TOOLS)
        choice = response.choices[0]
        messages.append(choice.message)
        if not choice.message.tool_calls:
            return choice.message.content
        for call in choice.message.tool_calls:
            args = json.loads(call.function.arguments or "{}")
            result = handlers[call.function.name](**args)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})

client = Client()
ask(client, "question")
"""


def scan(tmp_path, run_connector, source):
    (tmp_path / "app.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return [finding for finding in findings if finding.kind == Kind.AGENT]


@pytest.mark.parametrize(
    "source",
    [
        ANNOTATED,
        ANNOTATED.replace('ask(client, "question")', 'ask(question="question", client=client)'),
        ANNOTATED.replace('client = Client()\nask(client, "question")', 'ask(Client(), "question")'),
        ANNOTATED.replace("import OpenAI as Client", "import AzureOpenAI as Client"),
        ANNOTATED.replace("client = Client()\nask", "def main():\n    client = Client()\n    ask")
        + "\nmain()\n",
    ],
)
def test_annotated_client_requires_matching_constructed_argument(tmp_path, run_connector, source):
    agents = scan(tmp_path, run_connector, source)
    assert len(agents) == 1
    assert {"tool-use", "autonomous"} <= set(agents[0].capabilities)


@pytest.mark.parametrize(
    "source",
    [
        ANNOTATED.replace('ask(client, "question")', ""),
        ANNOTATED.replace("client = Client()", "client = unknown"),
        ANNOTATED.replace('ask(client, "question")', 'ask(unknown, "question")'),
        ANNOTATED.replace('ask(client, "question")', 'if False:\n    ask(client, "question")'),
        ANNOTATED.replace('ask(client, "question")', 'raise RuntimeError()\nask(client, "question")'),
        ANNOTATED.replace('ask(client, "question")', 'ask(client, "question")\nask(unknown, "question")'),
        ANNOTATED.replace('ask(client, "question")', "ask(*values, client=client)"),
        ANNOTATED.replace('ask(client, "question")', 'ask(client, "question", client=client)'),
        ANNOTATED.replace('ask(client, "question")', "ask(client)"),
        ANNOTATED.replace("    messages =", "    client = unknown\n    messages ="),
        ANNOTATED.replace("    messages =", "    del client\n    messages ="),
        ANNOTATED.replace("client: Client", "client: object"),
        ANNOTATED.replace("from openai import", "from local_sdk import"),
        ANNOTATED.replace("Client()", "Client\n"),
        ANNOTATED.replace("for turn in range(8):", "while False:"),
        ANNOTATED.replace("for call in choice.message.tool_calls:", "for call in unrelated.tool_calls:"),
        ANNOTATED.replace("handlers[call.function.name](**args)", "print(call.function.name, args)"),
        ANNOTATED.replace("choice = response.choices[0]", "choice = saved.choices[0]"),
        ANNOTATED.replace("choice = response.choices[0]", "choice = response.choices[1]"),
        ANNOTATED.replace(
            "choice = response.choices[0]", "choice = response.choices[0]\n        choice = saved"
        ),
    ],
)
def test_annotations_and_unconnected_client_flows_do_not_confirm_agents(tmp_path, run_connector, source):
    assert not scan(tmp_path, run_connector, source)


@pytest.mark.parametrize("case_id", ["python-openai-tool-loop-script", "litellm-proxy-docker-worker"])
def test_realistic_imported_dispatchers_are_detected(tmp_path, run_connector, case_id):
    corpus = json.loads((Path(__file__).parents[2] / "tools/evaluation/realistic_corpus.json").read_text())
    case = next(case for case in corpus["cases"] if case["id"] == case_id)
    for relative, contents in case["files"].items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert agents
    assert any(
        case["target"]["signature"] in [*finding.frameworks, *finding.model_providers] for finding in agents
    )
    assert any({"tool-use", "autonomous"} <= set(finding.capabilities) for finding in agents)


@pytest.mark.parametrize(
    "replacement",
    [
        "def run_tool(name, args):\n    return print(name, args)\n",
        "def run_tool(name, args):\n    return str(args)\n",
        "def run_tool(name, args):\n    return fake_handlers[name](**args)\n",
        "def run_tool(name, args):\n    return None\n    return fake_handlers[name](**args)\n",
    ],
)
def test_imported_dispatch_name_and_arguments_alone_do_not_prove_execution(
    tmp_path, run_connector, replacement
):
    source = ANNOTATED.replace("import json", "import json\nfrom tools import run_tool").replace(
        "handlers[call.function.name](**args)", "run_tool(call.function.name, args)"
    )
    (tmp_path / "tools.py").write_text(replacement)
    assert not scan(tmp_path, run_connector, source)
