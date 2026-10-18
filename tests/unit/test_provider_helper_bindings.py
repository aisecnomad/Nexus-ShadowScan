"""A typed provider parameter needs closed, constructor-bound call sites."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code.source_semantics import _python_bindings
from shadowscan.models import Kind

SOURCE = """from openai import OpenAI
import json

def ask(client: OpenAI, question: str):
    messages = [{"role": "user", "content": question}]
    while True:
        response = client.chat.completions.create(
            model="example", messages=messages,
            tools=[{"type": "function", "function": {"name": "lookup"}}],
        )
        message = response.choices[0].message
        if not message.tool_calls:
            return message.content
        for call in message.tool_calls:
            result = lookup(**json.loads(call.function.arguments))
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})

def main():
    client = OpenAI()
    return ask(client, "question")

main()
"""


def _requests(source):
    calls, _, _ = _python_bindings(source)
    return [
        call
        for call in calls
        if call.binding.module in {"openai", "anthropic"}
        and call.binding.symbol.endswith((".chat.completions.create", ".messages.create"))
    ]


@pytest.mark.parametrize(
    "source",
    [
        SOURCE,
        SOURCE.replace('ask(client, "question")', 'ask(client=client, question="question")'),
        SOURCE.replace("from openai import OpenAI", "from openai import OpenAI as Client")
        .replace("client: OpenAI", "client: Client")
        .replace("= OpenAI()", "= Client()"),
        SOURCE.replace("from openai import OpenAI", "import openai").replace("OpenAI", "openai.OpenAI"),
        SOURCE.replace("OpenAI", "AsyncOpenAI").replace("def ask(", "async def ask("),
        SOURCE.replace("def ask(client: OpenAI, question: str)", "def ask(client: OpenAI, /, question: str)"),
        SOURCE.replace(
            "def ask(client: OpenAI, question: str)", "def ask(*, client: OpenAI, question: str)"
        ).replace('ask(client, "question")', 'ask(client=client, question="question")'),
        SOURCE.replace(
            '    return ask(client, "question")', '    ask(client, "first")\n    return ask(client, "second")'
        ),
    ],
)
def test_closed_helper_follows_actual_provider_instance(source):
    requests = _requests(source)
    assert len(requests) == 1
    assert requests[0].binding.constructed


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.split("def main():")[0],
        SOURCE.replace('ask(client, "question")', 'ask(object(), "question")'),
        SOURCE.replace('ask(client, "question")', 'ask(OpenAI, "question")'),
        SOURCE.replace("import json", "import json\nfrom openai import AzureOpenAI").replace(
            "    client = OpenAI()", "    client = AzureOpenAI()"
        ),
        SOURCE.replace(
            '    return ask(client, "question")', '    ask(client, "first")\n    return ask(other, "second")'
        ),
        SOURCE + "runner = ask\n",
        SOURCE + "register(ask)\n",
        SOURCE.replace("def ask(", "@decorate\ndef ask("),
        SOURCE + "ask = replacement\n",
        SOURCE.replace('ask(client, "question")', 'ask(*[client, "question"])'),
        SOURCE.replace('ask(client, "question")', 'ask(**{"client": client, "question": "question"})'),
        SOURCE.replace('ask(client, "question")', "ask(client)"),
        SOURCE.replace('ask(client, "question")', 'ask(client, client=client, question="question")'),
        SOURCE.replace('ask(client, "question")', 'ask(client, "question", unknown=True)'),
        SOURCE.replace("    client = OpenAI()", "    client = OpenAI()\n    client = object()"),
        SOURCE.replace("    messages =", "    client = object()\n    messages =", 1),
        SOURCE.replace(
            "    messages =",
            "    def overwrite():\n        nonlocal client\n        client = object()\n    overwrite()\n    messages =",
            1,
        ),
        SOURCE.replace("    client = OpenAI()", "    OpenAI = object\n    client = OpenAI()"),
        SOURCE.replace("import json", "import json\nfrom elsewhere import *"),
        SOURCE.replace("client: OpenAI", 'client: "OpenAI"'),
        SOURCE.replace("client: OpenAI", "client: OpenAI.chat"),
        SOURCE + "def other(ask):\n    return ask()\n",
        SOURCE + "if False:\n    ask(unknown, 'question')\n",
        SOURCE.replace("def ask(", 'client = OpenAI()\nask(client, "early")\n\ndef ask('),
        SOURCE + "def overwrite():\n    global client\n    client = object()\n",
    ],
)
def test_annotation_and_uncertain_call_sites_do_not_establish_provider_provenance(source):
    assert not _requests(source)


def test_bound_helper_loop_is_an_agent(tmp_path, run_connector):
    (tmp_path / "assistant.py").write_text(SOURCE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "protocol.openai-function-calling" in agents[0].frameworks


def test_value_free_annotation_preserves_existing_binding():
    source = (
        "from openai import OpenAI\nclient = OpenAI()\nclient: OpenAI\nclient.chat.completions.create()\n"
    )
    assert len(_requests(source)) == 1


def test_value_free_annotation_without_local_binding_shadows_an_outer_import():
    source = (
        "from openai import OpenAI\ndef run():\n    OpenAI: type\n    OpenAI().chat.completions.create()\n"
    )
    assert not _requests(source)
