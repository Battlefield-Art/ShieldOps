"""Graph with a conditional edge for the conditional_edges fixture."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from tests.unit.scripts.codemods.fixtures.conditional_edges.models import ConditionalEdgesState
from tests.unit.scripts.codemods.fixtures.conditional_edges.nodes import (
    apply_action,
    detect,
    evaluate,
)


def _route(state) -> str:
    return "apply" if state.accepted else "end"


def create_conditional_edges_graph() -> StateGraph:
    graph = StateGraph(ConditionalEdgesState)
    graph.add_node("detect", detect)
    graph.add_node("evaluate", evaluate)
    graph.add_node("apply", apply_action)
    graph.set_entry_point("detect")
    graph.add_edge("detect", "evaluate")
    graph.add_conditional_edges(
        "evaluate",
        _route,
        {"apply": "apply", "end": END},
    )
    graph.add_edge("apply", END)
    return graph
