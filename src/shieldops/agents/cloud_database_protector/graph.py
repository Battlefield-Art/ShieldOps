"""LangGraph workflow definition for the Cloud Database
Protector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_database_protector.models import (
    CloudDatabaseProtectorState,
)
from shieldops.agents.cloud_database_protector.nodes import (
    audit_access,
    check_encryption,
    detect_anomalies,
    discover_databases,
    enforce_policies,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_database_protector"


def _should_enforce(
    state: CloudDatabaseProtectorState,
) -> str:
    """Route after anomaly detection: enforce if anomalies
    found or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.anomalies and state.enforce_mode:
        return "enforce_policies"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Database Protector LangGraph
    workflow.

    Workflow:
        discover_databases -> audit_access
            -> check_encryption -> detect_anomalies
            -> [anomalies+enforce? -> enforce_policies]
            -> generate_report -> END
    """
    graph = StateGraph(CloudDatabaseProtectorState)

    graph.add_node(
        "discover_databases",
        traced_node(f"{_AGENT}.discover_databases", _AGENT)(discover_databases),
    )
    graph.add_node(
        "audit_access",
        traced_node(f"{_AGENT}.audit_access", _AGENT)(audit_access),
    )
    graph.add_node(
        "check_encryption",
        traced_node(f"{_AGENT}.check_encryption", _AGENT)(check_encryption),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "enforce_policies",
        traced_node(f"{_AGENT}.enforce_policies", _AGENT)(enforce_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_databases")
    graph.add_edge("discover_databases", "audit_access")
    graph.add_edge("audit_access", "check_encryption")
    graph.add_edge("check_encryption", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        _should_enforce,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_database_protector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Database Protector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
