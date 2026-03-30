"""Root Cause Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.root_cause_analyzer.models import (
    RootCauseAnalyzerState,
)
from shieldops.agents.root_cause_analyzer.nodes import (
    build_graph,
    collect_signals,
    rank_causes,
    recommend_fixes,
    report,
    trace_causality,
)
from shieldops.agents.tracing import traced_node

_AGENT = "root_cause_analyzer"


def _check_error(
    state: RootCauseAnalyzerState,
) -> str:
    return "report" if state.error else "next"


def create_root_cause_analyzer_graph() -> StateGraph:
    """Build the Root Cause Analyzer workflow."""
    graph = StateGraph(RootCauseAnalyzerState)

    graph.add_node(
        "collect_signals",
        traced_node("rca.collect_signals", _AGENT)(collect_signals),
    )
    graph.add_node(
        "build_graph",
        traced_node("rca.build_graph", _AGENT)(build_graph),
    )
    graph.add_node(
        "trace_causality",
        traced_node("rca.trace_causality", _AGENT)(trace_causality),
    )
    graph.add_node(
        "rank_causes",
        traced_node("rca.rank_causes", _AGENT)(rank_causes),
    )
    graph.add_node(
        "recommend_fixes",
        traced_node("rca.recommend_fixes", _AGENT)(recommend_fixes),
    )
    graph.add_node(
        "report",
        traced_node("rca.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_signals")

    graph.add_conditional_edges(
        "collect_signals",
        _check_error,
        {"report": "report", "next": "build_graph"},
    )
    graph.add_conditional_edges(
        "build_graph",
        _check_error,
        {"report": "report", "next": "trace_causality"},
    )
    graph.add_conditional_edges(
        "trace_causality",
        _check_error,
        {"report": "report", "next": "rank_causes"},
    )
    graph.add_conditional_edges(
        "rank_causes",
        _check_error,
        {"report": "report", "next": "recommend_fixes"},
    )
    graph.add_edge("recommend_fixes", "report")
    graph.add_edge("report", END)

    return graph
