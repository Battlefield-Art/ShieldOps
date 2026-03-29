"""Playbook Optimizer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.playbook_optimizer.models import PlaybookOptimizerState
from shieldops.agents.playbook_optimizer.nodes import (
    analyze_executions,
    identify_bottlenecks,
    report,
    simulate,
    suggest_improvements,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "playbook_optimizer"


def _check_error(state: PlaybookOptimizerState) -> str:
    return "report" if state.error else "next"


def create_playbook_optimizer_graph() -> StateGraph:
    """Build the Playbook Optimizer workflow."""
    graph = StateGraph(PlaybookOptimizerState)

    graph.add_node(
        "analyze_executions",
        traced_node(f"{_AGENT}.analyze_executions", _AGENT)(analyze_executions),
    )
    graph.add_node(
        "identify_bottlenecks",
        traced_node(f"{_AGENT}.identify_bottlenecks", _AGENT)(identify_bottlenecks),
    )
    graph.add_node(
        "suggest_improvements",
        traced_node(f"{_AGENT}.suggest_improvements", _AGENT)(suggest_improvements),
    )
    graph.add_node(
        "simulate",
        traced_node(f"{_AGENT}.simulate", _AGENT)(simulate),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("analyze_executions")

    graph.add_conditional_edges(
        "analyze_executions",
        _check_error,
        {"next": "identify_bottlenecks", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_bottlenecks",
        _check_error,
        {"next": "suggest_improvements", "report": "report"},
    )
    graph.add_conditional_edges(
        "suggest_improvements",
        _check_error,
        {"next": "simulate", "report": "report"},
    )
    graph.add_conditional_edges(
        "simulate",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
