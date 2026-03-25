"""LangGraph workflow definition for the MCP Gateway Agent."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.mcp_gateway.models import MCPGatewayState
from shieldops.agents.mcp_gateway.nodes import (
    assess_security,
    detect_abuse,
    discover_servers,
    enforce_policies,
    generate_report,
    monitor_traffic,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "mcp_gateway"


def _should_monitor(state: MCPGatewayState) -> str:
    """Route after policy enforcement.

    If there was an error, skip to report. Otherwise continue to
    traffic monitoring.
    """
    if state.error:
        return "generate_report"
    return "monitor_traffic"


def create_mcp_gateway_graph() -> StateGraph:
    """Build the MCP Gateway Agent LangGraph workflow.

    Workflow::

        discover_servers
            -> assess_security
            -> enforce_policies
            -> [conditional: monitor_traffic | generate_report]
            -> detect_abuse
            -> generate_report
            -> END
    """
    graph = StateGraph(MCPGatewayState)

    graph.add_node(
        "discover_servers",
        traced_node(f"{_AGENT}.discover_servers", _AGENT)(discover_servers),
    )
    graph.add_node(
        "assess_security",
        traced_node(f"{_AGENT}.assess_security", _AGENT)(assess_security),
    )
    graph.add_node(
        "enforce_policies",
        traced_node(f"{_AGENT}.enforce_policies", _AGENT)(enforce_policies),
    )
    graph.add_node(
        "monitor_traffic",
        traced_node(f"{_AGENT}.monitor_traffic", _AGENT)(monitor_traffic),
    )
    graph.add_node(
        "detect_abuse",
        traced_node(f"{_AGENT}.detect_abuse", _AGENT)(detect_abuse),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_servers")
    graph.add_edge("discover_servers", "assess_security")
    graph.add_edge("assess_security", "enforce_policies")
    graph.add_conditional_edges(
        "enforce_policies",
        _should_monitor,
        {
            "monitor_traffic": "monitor_traffic",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("monitor_traffic", "detect_abuse")
    graph.add_edge("detect_abuse", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
