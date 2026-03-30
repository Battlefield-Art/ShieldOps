"""Capacity Intelligence Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.capacity_intelligence.models import (
    CapacityIntelligenceState,
)
from shieldops.agents.capacity_intelligence.nodes import (
    collect_utilization,
    forecast_demand,
    identify_bottlenecks,
    optimize_resources,
    plan_scaling,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "capacity_intelligence"


def _check_error(
    state: CapacityIntelligenceState,
) -> str:
    return "report" if state.error else "next"


def create_capacity_intelligence_graph() -> StateGraph:
    """Build the Capacity Intelligence workflow."""
    graph = StateGraph(CapacityIntelligenceState)

    graph.add_node(
        "collect_utilization",
        traced_node("ci.collect_utilization", _AGENT)(collect_utilization),
    )
    graph.add_node(
        "forecast_demand",
        traced_node("ci.forecast_demand", _AGENT)(forecast_demand),
    )
    graph.add_node(
        "identify_bottlenecks",
        traced_node("ci.identify_bottlenecks", _AGENT)(identify_bottlenecks),
    )
    graph.add_node(
        "optimize_resources",
        traced_node("ci.optimize_resources", _AGENT)(optimize_resources),
    )
    graph.add_node(
        "plan_scaling",
        traced_node("ci.plan_scaling", _AGENT)(plan_scaling),
    )
    graph.add_node(
        "report",
        traced_node("ci.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_utilization")

    graph.add_conditional_edges(
        "collect_utilization",
        _check_error,
        {"report": "report", "next": "forecast_demand"},
    )
    graph.add_conditional_edges(
        "forecast_demand",
        _check_error,
        {"report": "report", "next": "identify_bottlenecks"},
    )
    graph.add_conditional_edges(
        "identify_bottlenecks",
        _check_error,
        {"report": "report", "next": "optimize_resources"},
    )
    graph.add_conditional_edges(
        "optimize_resources",
        _check_error,
        {"report": "report", "next": "plan_scaling"},
    )
    graph.add_edge("plan_scaling", "report")
    graph.add_edge("report", END)

    return graph
