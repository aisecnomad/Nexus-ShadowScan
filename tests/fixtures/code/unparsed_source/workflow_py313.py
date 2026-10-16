from langgraph.graph import StateGraph
from typing import TypedDict

class State(TypedDict):
    messages: list

def make_graph[T = int]():
    graph = StateGraph(State)
    graph.add_node("agent", lambda state: state)
    graph.set_entry_point("agent")
    return graph.compile()
