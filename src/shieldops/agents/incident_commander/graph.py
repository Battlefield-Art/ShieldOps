"""LangGraph workflow definition for the Incident Commander Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.incident_commander.models import IncidentCommanderState
from shieldops.agents.incident_commander.nodes import (
    close_incident,
    coordinate_agents,
    monitor_and_decide,
    triage,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def route_after_monitor(state: IncidentCommanderState) -> str:
    """Route based on the latest decision from monitor_and_decide.

    Returns:
        - "close_incident" if all tasks resolved
        - END if escalated (human takes over)
        - "coordinate_agents" to loop back and re-dispatch/re-check
    """
    if state.error:
        return END

    # Check the latest decision
    if state.decisions:
        latest = state.decisions[-1]
        if latest.action == "resolve":
            return "close_incident"
        if latest.action == "escalate":
            return END

    # Default: loop back to coordination
    return "coordinate_agents"


def create_incident_commander_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Commander Agent LangGraph workflow.

    Workflow:
        triage -> coordinate_agents -> monitor_and_decide
            -> [conditional: resolved? -> close_incident -> END,
                             escalated? -> END,
                             else -> coordinate_agents loop]
    """
    graph = StateGraph(IncidentCommanderState)

    _agent = "incident_commander"

    # Add nodes (wrapped with OTEL tracing spans)
    graph.add_node(
        "triage",
        traced_node("incident_commander.triage", _agent)(triage),
    )
    graph.add_node(
        "coordinate_agents",
        traced_node("incident_commander.coordinate_agents", _agent)(coordinate_agents),
    )
    graph.add_node(
        "monitor_and_decide",
        traced_node("incident_commander.monitor_and_decide", _agent)(monitor_and_decide),
    )
    graph.add_node(
        "close_incident",
        traced_node("incident_commander.close_incident", _agent)(close_incident),
    )

    # Define edges
    graph.set_entry_point("triage")
    graph.add_edge("triage", "coordinate_agents")
    graph.add_edge("coordinate_agents", "monitor_and_decide")
    graph.add_conditional_edges(
        "monitor_and_decide",
        route_after_monitor,
        {
            "close_incident": "close_incident",
            "coordinate_agents": "coordinate_agents",
            END: END,
        },
    )
    graph.add_edge("close_incident", END)

    return graph
