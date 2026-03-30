"""Service Dependency Mapper Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.service_dependency_mapper.models import (
    ServiceDependencyMapperState,
)
from shieldops.agents.service_dependency_mapper.nodes import (
    assess_resilience,
    detect_cycles,
    discover_services,
    map_dependencies,
    report,
    trace_connections,
)
from shieldops.agents.tracing import traced_node

_AGENT = "service_dependency_mapper"


def _check_error(
    state: ServiceDependencyMapperState,
) -> str:
    return "report" if state.error else "next"


def create_service_dependency_mapper_graph() -> StateGraph:
    """Build the Service Dependency Mapper workflow."""
    graph = StateGraph(ServiceDependencyMapperState)

    graph.add_node(
        "discover_services",
        traced_node("sdm.discover_services", _AGENT)(discover_services),
    )
    graph.add_node(
        "trace_connections",
        traced_node("sdm.trace_connections", _AGENT)(trace_connections),
    )
    graph.add_node(
        "map_dependencies",
        traced_node("sdm.map_dependencies", _AGENT)(map_dependencies),
    )
    graph.add_node(
        "detect_cycles",
        traced_node("sdm.detect_cycles", _AGENT)(detect_cycles),
    )
    graph.add_node(
        "assess_resilience",
        traced_node("sdm.assess_resilience", _AGENT)(assess_resilience),
    )
    graph.add_node(
        "report",
        traced_node("sdm.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_services")

    graph.add_conditional_edges(
        "discover_services",
        _check_error,
        {"report": "report", "next": "trace_connections"},
    )
    graph.add_conditional_edges(
        "trace_connections",
        _check_error,
        {"report": "report", "next": "map_dependencies"},
    )
    graph.add_conditional_edges(
        "map_dependencies",
        _check_error,
        {"report": "report", "next": "detect_cycles"},
    )
    graph.add_conditional_edges(
        "detect_cycles",
        _check_error,
        {"report": "report", "next": "assess_resilience"},
    )
    graph.add_edge("assess_resilience", "report")
    graph.add_edge("report", END)

    return graph
