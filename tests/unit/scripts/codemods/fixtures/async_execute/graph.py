"""Graph for async_execute fixture."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from tests.unit.scripts.codemods.fixtures.async_execute.models import AsyncExecuteState
from tests.unit.scripts.codemods.fixtures.async_execute.nodes import collect, summarize


def create_async_execute_graph() -> StateGraph:
    graph = StateGraph(AsyncExecuteState)
    graph.add_node("collect", collect)
    graph.add_node("summarize", summarize)
    graph.set_entry_point("collect")
    graph.add_edge("collect", "summarize")
    graph.add_edge("summarize", END)
    return graph
