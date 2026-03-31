"""LangGraph workflow definition for the Wireless Security
Auditor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.wireless_security_auditor.models import (
    WirelessSecurityAuditorState,
)
from shieldops.agents.wireless_security_auditor.nodes import (
    assess_risk,
    check_encryption,
    detect_rogues,
    discover_networks,
    generate_report,
    scan_access_points,
)

_AGENT = "wireless_security_auditor"


def _should_assess(
    state: WirelessSecurityAuditorState,
) -> str:
    """Route after rogue detection: assess risk if
    findings exist or on error, else skip to report."""
    if state.error:
        return "generate_report"
    if state.rogue_count > 0 or state.non_compliant_count > 0:
        return "assess_risk"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Wireless Security Auditor LangGraph
    workflow.

    Workflow:
        discover_networks -> scan_access_points
            -> check_encryption -> detect_rogues
            -> [findings? -> assess_risk]
            -> generate_report -> END
    """
    graph = StateGraph(WirelessSecurityAuditorState)

    graph.add_node(
        "discover_networks",
        traced_node(f"{_AGENT}.discover_networks", _AGENT)(discover_networks),
    )
    graph.add_node(
        "scan_access_points",
        traced_node(f"{_AGENT}.scan_access_points", _AGENT)(scan_access_points),
    )
    graph.add_node(
        "check_encryption",
        traced_node(f"{_AGENT}.check_encryption", _AGENT)(check_encryption),
    )
    graph.add_node(
        "detect_rogues",
        traced_node(f"{_AGENT}.detect_rogues", _AGENT)(detect_rogues),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_networks")
    graph.add_edge("discover_networks", "scan_access_points")
    graph.add_edge("scan_access_points", "check_encryption")
    graph.add_edge("check_encryption", "detect_rogues")
    graph.add_conditional_edges(
        "detect_rogues",
        _should_assess,
        {
            "assess_risk": "assess_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_wireless_security_auditor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Wireless Security Auditor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
