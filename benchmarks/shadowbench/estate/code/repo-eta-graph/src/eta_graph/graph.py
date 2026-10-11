"""ETA replanning graph: fetch telemetry, draft a revised ETA, review it."""

import os
from typing import TypedDict

import anthropic
from langgraph.graph import END, StateGraph

MODEL = os.environ.get("ETA_GRAPH_MODEL", "claude-sonnet-4-5")


class EtaState(TypedDict, total=False):
    shipment_id: str
    telemetry: dict
    draft: str
    approved: bool


def draft_eta(state: EtaState) -> EtaState:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = client.messages.create(
        model=MODEL,
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Revise the ETA for shipment {state['shipment_id']} "
                    f"given this telemetry: {state['telemetry']}"
                ),
            }
        ],
    )
    return {"draft": message.content[0].text}


def review(state: EtaState) -> EtaState:
    draft = state.get("draft", "")
    return {"approved": bool(draft) and state.get("shipment_id", "") in draft}


def build_graph():
    graph = StateGraph(EtaState)
    graph.add_node("draft_eta", draft_eta)
    graph.add_node("review", review)
    graph.set_entry_point("draft_eta")
    graph.add_edge("draft_eta", "review")
    graph.add_edge("review", END)
    return graph.compile()
