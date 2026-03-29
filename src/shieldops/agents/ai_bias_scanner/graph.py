"""AI Bias Scanner Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ai_bias_scanner.models import AIBiasScannerState
from shieldops.agents.ai_bias_scanner.nodes import (
    assess_fairness,
    collect_data,
    compute_metrics,
    identify_groups,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ai_bias_scanner"


def _check_error(state: AIBiasScannerState) -> str:
    return "report" if state.error else "next"


def create_ai_bias_scanner_graph() -> StateGraph:
    """Build the AI Bias Scanner LangGraph workflow."""
    graph = StateGraph(AIBiasScannerState)

    graph.add_node(
        "collect_data",
        traced_node(f"{_AGENT}.collect_data", _AGENT)(collect_data),
    )
    graph.add_node(
        "identify_groups",
        traced_node(f"{_AGENT}.identify_groups", _AGENT)(identify_groups),
    )
    graph.add_node(
        "compute_metrics",
        traced_node(f"{_AGENT}.compute_metrics", _AGENT)(compute_metrics),
    )
    graph.add_node(
        "assess_fairness",
        traced_node(f"{_AGENT}.assess_fairness", _AGENT)(assess_fairness),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_data")

    graph.add_conditional_edges(
        "collect_data",
        _check_error,
        {"next": "identify_groups", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_groups",
        _check_error,
        {"next": "compute_metrics", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_metrics",
        _check_error,
        {"next": "assess_fairness", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_fairness",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
