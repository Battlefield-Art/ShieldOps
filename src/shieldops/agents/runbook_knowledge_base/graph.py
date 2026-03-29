"""Runbook Knowledge Base Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.runbook_knowledge_base.models import RunbookKnowledgeBaseState
from shieldops.agents.runbook_knowledge_base.nodes import (
    build_search,
    extract_patterns,
    feedback,
    index_runbooks,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "runbook_knowledge_base"


def _check_error(state: RunbookKnowledgeBaseState) -> str:
    return "report" if state.error else "next"


def create_runbook_knowledge_base_graph() -> StateGraph:
    """Build the Runbook Knowledge Base workflow."""
    graph = StateGraph(RunbookKnowledgeBaseState)

    graph.add_node(
        "index_runbooks",
        traced_node(f"{_AGENT}.index_runbooks", _AGENT)(index_runbooks),
    )
    graph.add_node(
        "extract_patterns",
        traced_node(f"{_AGENT}.extract_patterns", _AGENT)(extract_patterns),
    )
    graph.add_node(
        "build_search",
        traced_node(f"{_AGENT}.build_search", _AGENT)(build_search),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "feedback",
        traced_node(f"{_AGENT}.feedback", _AGENT)(feedback),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("index_runbooks")

    graph.add_conditional_edges(
        "index_runbooks",
        _check_error,
        {"next": "extract_patterns", "report": "report"},
    )
    graph.add_conditional_edges(
        "extract_patterns",
        _check_error,
        {"next": "build_search", "report": "report"},
    )
    graph.add_conditional_edges(
        "build_search",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_conditional_edges(
        "recommend",
        _check_error,
        {"next": "feedback", "report": "report"},
    )
    graph.add_edge("feedback", "report")
    graph.add_edge("report", END)

    return graph
