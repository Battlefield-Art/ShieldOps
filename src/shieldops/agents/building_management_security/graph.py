"""Building Management Security Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.building_management_security.models import BuildingManagementSecurityState
from shieldops.agents.building_management_security.nodes import (
    assess_risk,
    audit_configs,
    check_access,
    detect_anomalies,
    discover_systems,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "building_management_security"


def _check_error(state: BuildingManagementSecurityState) -> str:
    return "report" if state.error else "next"


def create_building_management_security_graph() -> StateGraph:
    """Build the Building Management Security LangGraph workflow."""
    graph = StateGraph(BuildingManagementSecurityState)

    graph.add_node(
        "discover_systems",
        traced_node(f"{_AGENT}.discover_systems", _AGENT)(discover_systems),
    )
    graph.add_node(
        "audit_configs",
        traced_node(f"{_AGENT}.audit_configs", _AGENT)(audit_configs),
    )
    graph.add_node(
        "check_access",
        traced_node(f"{_AGENT}.check_access", _AGENT)(check_access),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_systems")

    graph.add_conditional_edges(
        "discover_systems",
        _check_error,
        {"next": "audit_configs", "report": "report"},
    )
    graph.add_conditional_edges(
        "audit_configs",
        _check_error,
        {"next": "check_access", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_access",
        _check_error,
        {"next": "detect_anomalies", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_edge("assess_risk", "report")
    graph.add_edge("report", END)

    return graph
