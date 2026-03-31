"""LangGraph workflow definition for the Incident Cost
Tracker Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_cost_tracker.models import (
    IncidentCostTrackerState,
)
from shieldops.agents.incident_cost_tracker.nodes import (
    assess_regulatory,
    calculate_direct,
    estimate_indirect,
    forecast_total,
    generate_report,
    identify_incident,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_cost_tracker"


def _should_forecast(
    state: IncidentCostTrackerState,
) -> str:
    """Route after regulatory assessment: forecast if
    costs exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    total = state.total_direct_usd + state.total_indirect_usd + state.total_regulatory_usd
    if total > 0:
        return "forecast_total"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Cost Tracker LangGraph workflow.

    Workflow:
        identify_incident -> calculate_direct
            -> estimate_indirect -> assess_regulatory
            -> [costs? -> forecast_total]
            -> generate_report -> END
    """
    graph = StateGraph(IncidentCostTrackerState)

    graph.add_node(
        "identify_incident",
        traced_node(f"{_AGENT}.identify_incident", _AGENT)(identify_incident),
    )
    graph.add_node(
        "calculate_direct",
        traced_node(f"{_AGENT}.calculate_direct", _AGENT)(calculate_direct),
    )
    graph.add_node(
        "estimate_indirect",
        traced_node(f"{_AGENT}.estimate_indirect", _AGENT)(estimate_indirect),
    )
    graph.add_node(
        "assess_regulatory",
        traced_node(f"{_AGENT}.assess_regulatory", _AGENT)(assess_regulatory),
    )
    graph.add_node(
        "forecast_total",
        traced_node(f"{_AGENT}.forecast_total", _AGENT)(forecast_total),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("identify_incident")
    graph.add_edge("identify_incident", "calculate_direct")
    graph.add_edge("calculate_direct", "estimate_indirect")
    graph.add_edge("estimate_indirect", "assess_regulatory")
    graph.add_conditional_edges(
        "assess_regulatory",
        _should_forecast,
        {
            "forecast_total": "forecast_total",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("forecast_total", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_incident_cost_tracker_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Incident Cost Tracker
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
