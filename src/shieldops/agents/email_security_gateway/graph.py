"""LangGraph workflow for the Email Security Gateway Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.email_security_gateway.models import (
    EmailSecurityGatewayState,
)
from shieldops.agents.email_security_gateway.nodes import (
    analyze_headers,
    check_reputation,
    generate_report,
    ingest_email,
    quarantine_messages,
    scan_attachments,
)
from shieldops.agents.tracing import traced_node

_AGENT = "email_security_gateway"


def _should_scan_attachments(
    state: EmailSecurityGatewayState,
) -> str:
    """Route after header analysis based on results."""
    if state.error:
        return "generate_report"
    has_attachments = any(e.get("has_attachments") for e in state.ingested_emails)
    if has_attachments:
        return "scan_attachments"
    return "check_reputation"


def _should_quarantine(
    state: EmailSecurityGatewayState,
) -> str:
    """Route after reputation check."""
    if state.auth_failure_count > 0 or state.bad_sender_count > 0:
        return "quarantine_messages"
    return "quarantine_messages"


def create_email_security_gateway_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Email Security Gateway LangGraph.

    Workflow:
        ingest_email
          -> analyze_headers
          -> [has_attachments?] -> scan_attachments
          -> check_reputation
          -> quarantine_messages
          -> generate_report
    """
    graph = StateGraph(EmailSecurityGatewayState)

    graph.add_node(
        "ingest_email",
        traced_node(
            f"{_AGENT}.ingest_email",
            _AGENT,
        )(ingest_email),
    )
    graph.add_node(
        "analyze_headers",
        traced_node(
            f"{_AGENT}.analyze_headers",
            _AGENT,
        )(analyze_headers),
    )
    graph.add_node(
        "scan_attachments",
        traced_node(
            f"{_AGENT}.scan_attachments",
            _AGENT,
        )(scan_attachments),
    )
    graph.add_node(
        "check_reputation",
        traced_node(
            f"{_AGENT}.check_reputation",
            _AGENT,
        )(check_reputation),
    )
    graph.add_node(
        "quarantine_messages",
        traced_node(
            f"{_AGENT}.quarantine_messages",
            _AGENT,
        )(quarantine_messages),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("ingest_email")
    graph.add_edge("ingest_email", "analyze_headers")
    graph.add_conditional_edges(
        "analyze_headers",
        _should_scan_attachments,
        {
            "scan_attachments": "scan_attachments",
            "check_reputation": "check_reputation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("scan_attachments", "check_reputation")
    graph.add_conditional_edges(
        "check_reputation",
        _should_quarantine,
        {
            "quarantine_messages": "quarantine_messages",
        },
    )
    graph.add_edge("quarantine_messages", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
