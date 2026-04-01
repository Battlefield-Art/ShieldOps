"""LangGraph workflow for the Security Orchestration Mesh Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_orchestration_mesh.models import (
    SecurityOrchestrationMeshState,
)
from shieldops.agents.security_orchestration_mesh.nodes import (
    aggregate_results,
    coordinate_execution,
    discover_regions,
    distribute_tasks,
    generate_report,
    map_capabilities,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_orchestration_mesh"


def _should_distribute(
    state: SecurityOrchestrationMeshState,
) -> str:
    """Route after capability mapping."""
    if state.error:
        return "generate_report"
    if state.capabilities:
        return "distribute_tasks"
    return "generate_report"


def _should_aggregate(
    state: SecurityOrchestrationMeshState,
) -> str:
    """Route after coordination."""
    if state.coordination_results:
        return "aggregate_results"
    return "generate_report"


def create_security_orchestration_mesh_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Orchestration Mesh LangGraph.

    Workflow:
        discover_regions -> map_capabilities
          -> [has_caps?] -> distribute_tasks -> coordinate_execution
          -> [has_results?] -> aggregate_results -> generate_report
    """
    graph = StateGraph(SecurityOrchestrationMeshState)

    graph.add_node(
        "discover_regions",
        traced_node(f"{_AGENT}.discover_regions", _AGENT)(discover_regions),
    )
    graph.add_node(
        "map_capabilities",
        traced_node(f"{_AGENT}.map_capabilities", _AGENT)(map_capabilities),
    )
    graph.add_node(
        "distribute_tasks",
        traced_node(f"{_AGENT}.distribute_tasks", _AGENT)(distribute_tasks),
    )
    graph.add_node(
        "coordinate_execution",
        traced_node(f"{_AGENT}.coordinate_execution", _AGENT)(coordinate_execution),
    )
    graph.add_node(
        "aggregate_results",
        traced_node(f"{_AGENT}.aggregate_results", _AGENT)(aggregate_results),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("discover_regions")
    graph.add_edge("discover_regions", "map_capabilities")
    graph.add_conditional_edges(
        "map_capabilities",
        _should_distribute,
        {
            "distribute_tasks": "distribute_tasks",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("distribute_tasks", "coordinate_execution")
    graph.add_conditional_edges(
        "coordinate_execution",
        _should_aggregate,
        {
            "aggregate_results": "aggregate_results",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("aggregate_results", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
