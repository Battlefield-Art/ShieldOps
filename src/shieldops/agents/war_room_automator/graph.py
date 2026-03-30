"""War Room Automator — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import WarRoomAutomatorState
from .nodes import (
    assemble_team,
    coordinate_actions,
    create_room,
    detect_incident,
    report,
    share_context,
)
from .tools import WarRoomAutomatorToolkit

_AGENT = "war_room_automator"


def _check_error(
    state: WarRoomAutomatorState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: WarRoomAutomatorToolkit,
) -> StateGraph:
    """Build the War Room Automator graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _detect(s: Any) -> dict[str, Any]:
        return await detect_incident(_d(s))

    async def _create(s: Any) -> dict[str, Any]:
        return await create_room(_d(s))

    async def _assemble(s: Any) -> dict[str, Any]:
        return await assemble_team(_d(s))

    async def _share(s: Any) -> dict[str, Any]:
        return await share_context(_d(s))

    async def _coordinate(s: Any) -> dict[str, Any]:
        return await coordinate_actions(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(WarRoomAutomatorState)
    g.add_node(
        "detect_incident",
        traced_node("wra.detect", _AGENT)(_detect),
    )
    g.add_node(
        "create_room",
        traced_node("wra.create", _AGENT)(_create),
    )
    g.add_node(
        "assemble_team",
        traced_node("wra.assemble", _AGENT)(_assemble),
    )
    g.add_node(
        "share_context",
        traced_node("wra.share", _AGENT)(_share),
    )
    g.add_node(
        "coordinate_actions",
        traced_node("wra.coordinate", _AGENT)(_coordinate),
    )
    g.add_node(
        "report",
        traced_node("wra.report", _AGENT)(_report),
    )

    g.set_entry_point("detect_incident")
    g.add_edge("detect_incident", "create_room")
    g.add_edge("create_room", "assemble_team")
    g.add_edge("assemble_team", "share_context")
    g.add_edge("share_context", "coordinate_actions")
    g.add_edge("coordinate_actions", "report")
    g.add_edge("report", END)

    return g


def create_war_room_automator_graph(
    chat_service: Any | None = None,
    oncall_service: Any | None = None,
) -> StateGraph:
    """Factory to create the war room graph."""
    toolkit = WarRoomAutomatorToolkit(
        chat_service=chat_service,
        oncall_service=oncall_service,
    )
    return build_graph(toolkit)
