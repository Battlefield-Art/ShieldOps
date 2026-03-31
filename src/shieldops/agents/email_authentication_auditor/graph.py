"""LangGraph workflow definition for the Email
Authentication Auditor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.email_authentication_auditor.models import (
    EmailAuthenticationAuditorState,
)
from shieldops.agents.email_authentication_auditor.nodes import (
    assess_posture,
    check_dkim,
    check_dmarc,
    check_spf,
    generate_report,
    scan_domains,
)
from shieldops.agents.tracing import traced_node

_AGENT = "email_authentication_auditor"


def _should_assess(
    state: EmailAuthenticationAuditorState,
) -> str:
    """Route after DMARC check: assess if results
    exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if len(state.dmarc_results) > 0:
        return "assess_posture"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Email Authentication Auditor workflow.

    Workflow:
        scan_domains -> check_spf -> check_dkim
            -> check_dmarc -> [results? -> assess_posture]
            -> generate_report -> END
    """
    graph = StateGraph(EmailAuthenticationAuditorState)

    graph.add_node(
        "scan_domains",
        traced_node(f"{_AGENT}.scan_domains", _AGENT)(scan_domains),
    )
    graph.add_node(
        "check_spf",
        traced_node(f"{_AGENT}.check_spf", _AGENT)(check_spf),
    )
    graph.add_node(
        "check_dkim",
        traced_node(f"{_AGENT}.check_dkim", _AGENT)(check_dkim),
    )
    graph.add_node(
        "check_dmarc",
        traced_node(f"{_AGENT}.check_dmarc", _AGENT)(check_dmarc),
    )
    graph.add_node(
        "assess_posture",
        traced_node(f"{_AGENT}.assess_posture", _AGENT)(assess_posture),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("scan_domains")
    graph.add_edge("scan_domains", "check_spf")
    graph.add_edge("check_spf", "check_dkim")
    graph.add_edge("check_dkim", "check_dmarc")
    graph.add_conditional_edges(
        "check_dmarc",
        _should_assess,
        {
            "assess_posture": "assess_posture",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_posture", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_email_authentication_auditor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Email Authentication Auditor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
