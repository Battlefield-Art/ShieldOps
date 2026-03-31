"""LangGraph workflow definition for the Security Mesh
Orchestrator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_mesh_orchestrator.models import (
    SecurityMeshOrchestratorState,
)
from shieldops.agents.security_mesh_orchestrator.nodes import (
    detect_anomalies,
    discover_services,
    enforce_mtls,
    generate_report,
    map_mesh,
    monitor_traffic,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_mesh_orchestrator"


def _should_report(
    state: SecurityMeshOrchestratorState,
) -> str:
    """Route after anomaly detection: skip traffic
    monitoring on error, otherwise continue to report."""
    if state.error:
        return "generate_report"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Mesh Orchestrator LangGraph
    workflow.

    Workflow:
        discover_services -> map_mesh -> enforce_mtls
            -> monitor_traffic -> detect_anomalies
            -> generate_report -> END
    """
    graph = StateGraph(SecurityMeshOrchestratorState)

    graph.add_node(
        "discover_services",
        traced_node(f"{_AGENT}.discover_services", _AGENT)(discover_services),
    )
    graph.add_node(
        "map_mesh",
        traced_node(f"{_AGENT}.map_mesh", _AGENT)(map_mesh),
    )
    graph.add_node(
        "enforce_mtls",
        traced_node(f"{_AGENT}.enforce_mtls", _AGENT)(enforce_mtls),
    )
    graph.add_node(
        "monitor_traffic",
        traced_node(f"{_AGENT}.monitor_traffic", _AGENT)(monitor_traffic),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_services")
    graph.add_edge("discover_services", "map_mesh")
    graph.add_edge("map_mesh", "enforce_mtls")
    graph.add_edge("enforce_mtls", "monitor_traffic")
    graph.add_edge("monitor_traffic", "detect_anomalies")
    graph.add_edge("detect_anomalies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_mesh_orchestrator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Mesh Orchestrator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
