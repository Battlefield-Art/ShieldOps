"""API Gateway Security Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.api_gateway_security.models import (
    APIGatewaySecurityState,
)
from shieldops.agents.api_gateway_security.nodes import (
    analyze_traffic,
    detect_abuse,
    enforce_policies,
    generate_alerts,
    report,
    scan_endpoints,
)
from shieldops.agents.tracing import traced_node

_AGENT = "api_gateway_security"


def _check_error(
    state: APIGatewaySecurityState,
) -> str:
    return "report" if state.error else "next"


def create_api_gateway_security_graph() -> StateGraph:
    """Build the API Gateway Security workflow."""
    graph = StateGraph(APIGatewaySecurityState)

    graph.add_node(
        "scan_endpoints",
        traced_node("ags.scan_endpoints", _AGENT)(scan_endpoints),
    )
    graph.add_node(
        "analyze_traffic",
        traced_node("ags.analyze_traffic", _AGENT)(analyze_traffic),
    )
    graph.add_node(
        "detect_abuse",
        traced_node("ags.detect_abuse", _AGENT)(detect_abuse),
    )
    graph.add_node(
        "enforce_policies",
        traced_node("ags.enforce_policies", _AGENT)(enforce_policies),
    )
    graph.add_node(
        "generate_alerts",
        traced_node("ags.generate_alerts", _AGENT)(generate_alerts),
    )
    graph.add_node(
        "report",
        traced_node("ags.report", _AGENT)(report),
    )

    graph.set_entry_point("scan_endpoints")

    graph.add_conditional_edges(
        "scan_endpoints",
        _check_error,
        {"report": "report", "next": "analyze_traffic"},
    )
    graph.add_conditional_edges(
        "analyze_traffic",
        _check_error,
        {"report": "report", "next": "detect_abuse"},
    )
    graph.add_conditional_edges(
        "detect_abuse",
        _check_error,
        {
            "report": "report",
            "next": "enforce_policies",
        },
    )
    graph.add_conditional_edges(
        "enforce_policies",
        _check_error,
        {
            "report": "report",
            "next": "generate_alerts",
        },
    )
    graph.add_edge("generate_alerts", "report")
    graph.add_edge("report", END)

    return graph
