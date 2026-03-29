"""Incident Cost Calculator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_cost_calculator.models import IncidentCostCalculatorState
from shieldops.agents.incident_cost_calculator.nodes import (
    benchmark,
    compute_direct,
    compute_indirect,
    gather_metrics,
    project_long_term,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_cost_calculator"


def _check_error(state: IncidentCostCalculatorState) -> str:
    return "report" if state.error else "next"


def create_incident_cost_calculator_graph() -> StateGraph:
    """Build the Incident Cost Calculator workflow."""
    graph = StateGraph(IncidentCostCalculatorState)

    graph.add_node(
        "gather_metrics",
        traced_node(f"{_AGENT}.gather_metrics", _AGENT)(gather_metrics),
    )
    graph.add_node(
        "compute_direct",
        traced_node(f"{_AGENT}.compute_direct", _AGENT)(compute_direct),
    )
    graph.add_node(
        "compute_indirect",
        traced_node(f"{_AGENT}.compute_indirect", _AGENT)(compute_indirect),
    )
    graph.add_node(
        "project_long_term",
        traced_node(f"{_AGENT}.project_long_term", _AGENT)(project_long_term),
    )
    graph.add_node(
        "benchmark",
        traced_node(f"{_AGENT}.benchmark", _AGENT)(benchmark),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("gather_metrics")

    graph.add_conditional_edges(
        "gather_metrics",
        _check_error,
        {"next": "compute_direct", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_direct",
        _check_error,
        {"next": "compute_indirect", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_indirect",
        _check_error,
        {"next": "project_long_term", "report": "report"},
    )
    graph.add_conditional_edges(
        "project_long_term",
        _check_error,
        {"next": "benchmark", "report": "report"},
    )
    graph.add_edge("benchmark", "report")
    graph.add_edge("report", END)

    return graph
