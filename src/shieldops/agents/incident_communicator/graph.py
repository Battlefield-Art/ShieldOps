"""LangGraph workflow definition for the Incident Communicator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_communicator.models import (
    IncidentCommunicatorState,
)
from shieldops.agents.incident_communicator.nodes import (
    draft_messages,
    identify_stakeholders,
    report,
    select_channels,
    send_notifications,
    track_acks,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_communicator"


def create_incident_communicator_graph() -> StateGraph:
    """Build the Incident Communicator Agent LangGraph workflow.

    Workflow:
        identify_stakeholders -> draft_messages -> select_channels
        -> send_notifications -> track_acks -> report -> END

    Error edges route directly to report for graceful degradation.
    """
    graph = StateGraph(IncidentCommunicatorState)

    graph.add_node(
        "identify_stakeholders",
        traced_node(
            "incident_communicator.identify_stakeholders",
            _AGENT,
        )(identify_stakeholders),
    )
    graph.add_node(
        "draft_messages",
        traced_node(
            "incident_communicator.draft_messages",
            _AGENT,
        )(draft_messages),
    )
    graph.add_node(
        "select_channels",
        traced_node(
            "incident_communicator.select_channels",
            _AGENT,
        )(select_channels),
    )
    graph.add_node(
        "send_notifications",
        traced_node(
            "incident_communicator.send_notifications",
            _AGENT,
        )(send_notifications),
    )
    graph.add_node(
        "track_acks",
        traced_node(
            "incident_communicator.track_acks",
            _AGENT,
        )(track_acks),
    )
    graph.add_node(
        "report",
        traced_node(
            "incident_communicator.report",
            _AGENT,
        )(report),
    )

    # Linear pipeline with error edges to report
    graph.set_entry_point("identify_stakeholders")

    def _route_or_report(field: str, next_node: str):  # noqa: ANN202
        """Return a router that checks for errors before proceeding."""

        def _router(state: IncidentCommunicatorState) -> str:
            if state.error:
                return "report"
            return next_node

        return _router

    graph.add_conditional_edges(
        "identify_stakeholders",
        _route_or_report("error", "draft_messages"),
        {"draft_messages": "draft_messages", "report": "report"},
    )
    graph.add_conditional_edges(
        "draft_messages",
        _route_or_report("error", "select_channels"),
        {"select_channels": "select_channels", "report": "report"},
    )
    graph.add_conditional_edges(
        "select_channels",
        _route_or_report("error", "send_notifications"),
        {
            "send_notifications": "send_notifications",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "send_notifications",
        _route_or_report("error", "track_acks"),
        {"track_acks": "track_acks", "report": "report"},
    )
    graph.add_edge("track_acks", "report")
    graph.add_edge("report", END)

    return graph
