"""LangGraph workflow definition for the Security Mesh Orchestrator Agent."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityMeshOrchestratorState
from .nodes import (
    detect_anomalies,
    discover_services,
    enforce_mtls,
    generate_report,
    map_mesh,
    monitor_traffic,
)
from .tools import Any


def build_graph(toolkit: Any):  # type: ignore[no-untyped-def]
    """Build the security_mesh_orchestrator agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityMeshOrchestratorState,
        [
            ("discover_services", discover_services),
            ("map_mesh", map_mesh),
            ("enforce_mtls", enforce_mtls),
            ("monitor_traffic", monitor_traffic),
            ("detect_anomalies", detect_anomalies),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_mesh_orchestrator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Mesh Orchestrator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
