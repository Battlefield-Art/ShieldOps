"""LangGraph workflow definition for the Security
Telemetry Optimizer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_telemetry_optimizer.models import (
    SecurityTelemetryOptimizerState,
)
from shieldops.agents.security_telemetry_optimizer.nodes import (
    analyze_volume,
    detect_waste,
    generate_report,
    inventory_sources,
    optimize_routing,
    validate_quality,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_telemetry_optimizer"


def _should_validate(
    state: SecurityTelemetryOptimizerState,
) -> str:
    """Route after optimization: validate if optimizations
    exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if len(state.optimizations) > 0:
        return "validate_quality"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Telemetry Optimizer LangGraph
    workflow.

    Workflow:
        inventory_sources -> analyze_volume
            -> detect_waste -> optimize_routing
            -> [optimizations? -> validate_quality]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityTelemetryOptimizerState)

    graph.add_node(
        "inventory_sources",
        traced_node(f"{_AGENT}.inventory_sources", _AGENT)(inventory_sources),
    )
    graph.add_node(
        "analyze_volume",
        traced_node(f"{_AGENT}.analyze_volume", _AGENT)(analyze_volume),
    )
    graph.add_node(
        "detect_waste",
        traced_node(f"{_AGENT}.detect_waste", _AGENT)(detect_waste),
    )
    graph.add_node(
        "optimize_routing",
        traced_node(f"{_AGENT}.optimize_routing", _AGENT)(optimize_routing),
    )
    graph.add_node(
        "validate_quality",
        traced_node(f"{_AGENT}.validate_quality", _AGENT)(validate_quality),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("inventory_sources")
    graph.add_edge("inventory_sources", "analyze_volume")
    graph.add_edge("analyze_volume", "detect_waste")
    graph.add_edge("detect_waste", "optimize_routing")
    graph.add_conditional_edges(
        "optimize_routing",
        _should_validate,
        {
            "validate_quality": "validate_quality",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_quality", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_telemetry_optimizer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Telemetry Optimizer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
