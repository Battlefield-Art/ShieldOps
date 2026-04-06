"""War Room Automator — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: WarRoomAutomatorToolkit):  # type: ignore[no-untyped-def]
    """Build the war_room_automator agent graph (linear sequence)."""
    return build_linear_graph(
        WarRoomAutomatorState,
        [
            ("detect_incident", detect_incident),
            ("create_room", create_room),
            ("assemble_team", assemble_team),
            ("share_context", share_context),
            ("coordinate_actions", coordinate_actions),
            ("report", report),
        ],
        toolkit=toolkit,
    )


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
