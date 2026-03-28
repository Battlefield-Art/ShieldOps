"""LangGraph workflow for the Auto Ticket Manager Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.auto_ticket_manager.models import (
    AutoTicketManagerState,
)
from shieldops.agents.auto_ticket_manager.nodes import (
    assign_owners,
    classify_tickets,
    create_tickets,
    generate_report,
    receive_findings,
    track_sla,
)
from shieldops.agents.tracing import traced_node

_AGENT = "auto_ticket_manager"


def _has_findings(
    state: AutoTicketManagerState,
) -> str:
    """Route based on whether findings exist."""
    if state.error:
        return END
    if not state.findings_received:
        return "generate_report"
    return "classify_tickets"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Auto Ticket Manager StateGraph.

    Workflow:
        receive_findings
        -> [no findings? -> generate_report -> END]
        -> classify_tickets -> create_tickets
        -> assign_owners -> track_sla
        -> generate_report -> END
    """
    graph = StateGraph(AutoTicketManagerState)

    graph.add_node(
        "receive_findings",
        traced_node(f"{_AGENT}.receive_findings", _AGENT)(receive_findings),
    )
    graph.add_node(
        "classify_tickets",
        traced_node(f"{_AGENT}.classify_tickets", _AGENT)(classify_tickets),
    )
    graph.add_node(
        "create_tickets",
        traced_node(f"{_AGENT}.create_tickets", _AGENT)(create_tickets),
    )
    graph.add_node(
        "assign_owners",
        traced_node(f"{_AGENT}.assign_owners", _AGENT)(assign_owners),
    )
    graph.add_node(
        "track_sla",
        traced_node(f"{_AGENT}.track_sla", _AGENT)(track_sla),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("receive_findings")
    graph.add_conditional_edges(
        "receive_findings",
        _has_findings,
        {
            "classify_tickets": "classify_tickets",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("classify_tickets", "create_tickets")
    graph.add_edge("create_tickets", "assign_owners")
    graph.add_edge("assign_owners", "track_sla")
    graph.add_edge("track_sla", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_auto_ticket_manager_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Auto Ticket Manager graph."""
    return build_graph()
