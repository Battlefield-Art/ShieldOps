"""LangGraph workflow definition for the Security Ticket
Automator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_ticket_automator.models import (
    SecurityTicketAutomatorState,
)
from shieldops.agents.security_ticket_automator.nodes import (
    assign_owner,
    create_ticket,
    detect_issue,
    enrich_context,
    generate_report,
    track_sla,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_ticket_automator"


def _should_track_sla(
    state: SecurityTicketAutomatorState,
) -> str:
    """Route after assignment: track SLA if tickets exist
    or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.tickets_created > 0:
        return "track_sla"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Ticket Automator LangGraph
    workflow.

    Workflow:
        detect_issue -> enrich_context -> create_ticket
            -> assign_owner -> [tickets? -> track_sla]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityTicketAutomatorState)

    graph.add_node(
        "detect_issue",
        traced_node(f"{_AGENT}.detect_issue", _AGENT)(detect_issue),
    )
    graph.add_node(
        "enrich_context",
        traced_node(f"{_AGENT}.enrich_context", _AGENT)(enrich_context),
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
        "track_sla",
        traced_node(f"{_AGENT}.track_sla", _AGENT)(track_sla),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("detect_issue")
    graph.add_edge("detect_issue", "enrich_context")
    graph.add_edge("enrich_context", "create_ticket")
    graph.add_edge("create_ticket", "assign_owner")
    graph.add_conditional_edges(
        "assign_owner",
        _should_track_sla,
        {
            "track_sla": "track_sla",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("track_sla", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_ticket_automator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Ticket Automator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
