"""Ticket Automation Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ticket_automation.models import TicketAutomationState
from shieldops.agents.ticket_automation.nodes import (
    assign_owner,
    classify_event,
    create_ticket,
    report,
    set_sla,
    track,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ticket_automation"


def _check_error(state: TicketAutomationState) -> str:
    return "report" if state.error else "next"


def create_ticket_automation_graph() -> StateGraph:
    """Build the Ticket Automation workflow."""
    graph = StateGraph(TicketAutomationState)

    graph.add_node(
        "classify_event",
        traced_node(f"{_AGENT}.classify_event", _AGENT)(classify_event),
    )
    graph.add_node(
        "create_ticket",
        traced_node(f"{_AGENT}.create_ticket", _AGENT)(create_ticket),
    )
    graph.add_node(
        "assign_owner",
        traced_node(f"{_AGENT}.assign_owner", _AGENT)(assign_owner),
    )
    graph.add_node(
        "set_sla",
        traced_node(f"{_AGENT}.set_sla", _AGENT)(set_sla),
    )
    graph.add_node(
        "track",
        traced_node(f"{_AGENT}.track", _AGENT)(track),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("classify_event")

    graph.add_conditional_edges(
        "classify_event",
        _check_error,
        {"next": "create_ticket", "report": "report"},
    )
    graph.add_conditional_edges(
        "create_ticket",
        _check_error,
        {"next": "assign_owner", "report": "report"},
    )
    graph.add_conditional_edges(
        "assign_owner",
        _check_error,
        {"next": "set_sla", "report": "report"},
    )
    graph.add_conditional_edges(
        "set_sla",
        _check_error,
        {"next": "track", "report": "report"},
    )
    graph.add_edge("track", "report")
    graph.add_edge("report", END)

    return graph
