"""LangGraph workflow definition for the Security Alert
Router Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_alert_router.models import (
    SecurityAlertRouterState,
)
from shieldops.agents.security_alert_router.nodes import (
    classify_alerts,
    determine_owner,
    generate_report,
    receive_alerts,
    route_to_team,
    track_acknowledgment,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_alert_router"


def _should_track(
    state: SecurityAlertRouterState,
) -> str:
    """Route after routing: track ack if routed or on
    error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.routing_records:
        return "track_acknowledgment"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Alert Router LangGraph workflow.

    Workflow:
        receive_alerts -> classify_alerts
            -> determine_owner -> route_to_team
            -> [routed? -> track_acknowledgment]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityAlertRouterState)

    graph.add_node(
        "receive_alerts",
        traced_node(f"{_AGENT}.receive_alerts", _AGENT)(receive_alerts),
    )
    graph.add_node(
        "classify_alerts",
        traced_node(f"{_AGENT}.classify_alerts", _AGENT)(classify_alerts),
    )
    graph.add_node(
        "determine_owner",
        traced_node(f"{_AGENT}.determine_owner", _AGENT)(determine_owner),
    )
    graph.add_node(
        "route_to_team",
        traced_node(f"{_AGENT}.route_to_team", _AGENT)(route_to_team),
    )
    graph.add_node(
        "track_acknowledgment",
        traced_node(f"{_AGENT}.track_acknowledgment", _AGENT)(track_acknowledgment),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("receive_alerts")
    graph.add_edge("receive_alerts", "classify_alerts")
    graph.add_edge("classify_alerts", "determine_owner")
    graph.add_edge("determine_owner", "route_to_team")
    graph.add_conditional_edges(
        "route_to_team",
        _should_track,
        {
            "track_acknowledgment": "track_acknowledgment",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("track_acknowledgment", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_alert_router_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Alert Router
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
