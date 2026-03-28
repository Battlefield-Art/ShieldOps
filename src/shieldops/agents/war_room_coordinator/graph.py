"""LangGraph workflow for the War Room Coordinator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.war_room_coordinator.models import (
    WarRoomCoordinatorState,
)
from shieldops.agents.war_room_coordinator.nodes import (
    assign_roles,
    coordinate_comms,
    maintain_timeline,
    open_war_room,
    report,
    track_actions,
)

_AGENT = "war_room_coordinator"


def _check_error(
    state: WarRoomCoordinatorState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "continue"


def create_war_room_coordinator_graph() -> StateGraph:
    """Build the War Room Coordinator workflow.

    Workflow:
        open_war_room
            -> [error? -> report -> END]
            -> assign_roles
            -> [error? -> report -> END]
            -> track_actions
            -> [error? -> report -> END]
            -> maintain_timeline
            -> [error? -> report -> END]
            -> coordinate_comms
            -> report -> END
    """
    graph = StateGraph(WarRoomCoordinatorState)

    graph.add_node(
        "open_war_room",
        traced_node(
            "war_room_coordinator.open_war_room",
            _AGENT,
        )(open_war_room),
    )
    graph.add_node(
        "assign_roles",
        traced_node(
            "war_room_coordinator.assign_roles",
            _AGENT,
        )(assign_roles),
    )
    graph.add_node(
        "track_actions",
        traced_node(
            "war_room_coordinator.track_actions",
            _AGENT,
        )(track_actions),
    )
    graph.add_node(
        "maintain_timeline",
        traced_node(
            "war_room_coordinator.maintain_timeline",
            _AGENT,
        )(maintain_timeline),
    )
    graph.add_node(
        "coordinate_comms",
        traced_node(
            "war_room_coordinator.coordinate_comms",
            _AGENT,
        )(coordinate_comms),
    )
    graph.add_node(
        "report",
        traced_node(
            "war_room_coordinator.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("open_war_room")

    graph.add_conditional_edges(
        "open_war_room",
        _check_error,
        {
            "report": "report",
            "continue": "assign_roles",
        },
    )
    graph.add_conditional_edges(
        "assign_roles",
        _check_error,
        {
            "report": "report",
            "continue": "track_actions",
        },
    )
    graph.add_conditional_edges(
        "track_actions",
        _check_error,
        {
            "report": "report",
            "continue": "maintain_timeline",
        },
    )
    graph.add_conditional_edges(
        "maintain_timeline",
        _check_error,
        {
            "report": "report",
            "continue": "coordinate_comms",
        },
    )
    graph.add_edge("coordinate_comms", "report")
    graph.add_edge("report", END)

    return graph
