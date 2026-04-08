"""Canonical linear graph with three nodes."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from tests.unit.scripts.codemods.fixtures.canonical_run.models import CanonicalRunState
from tests.unit.scripts.codemods.fixtures.canonical_run.nodes import (
    finalize,
    investigate,
    triage,
)


def create_canonical_run_graph() -> StateGraph:
    graph = StateGraph(CanonicalRunState)
    graph.add_node("triage", triage)
    graph.add_node("investigate", investigate)
    graph.add_node("finalize", finalize)
    graph.set_entry_point("triage")
    graph.add_edge("triage", "investigate")
    graph.add_edge("investigate", "finalize")
    graph.add_edge("finalize", END)
    return graph
