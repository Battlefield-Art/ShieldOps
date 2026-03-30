"""Multi Cloud Orchestrator — LangGraph definition."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import MultiCloudOrchestratorState
from .nodes import (
    compare_pricing,
    discover_resources,
    execute_migration,
    normalize_inventory,
    optimize_placement,
    report,
)

logger = structlog.get_logger()

_AGENT = "multi_cloud_orchestrator"


def _check_error(
    state: MultiCloudOrchestratorState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_multi_cloud_orchestrator_graph() -> StateGraph[MultiCloudOrchestratorState]:
    """Build the Multi Cloud Orchestrator graph.

    Flow:
        discover_resources -> normalize_inventory
        -> compare_pricing -> optimize_placement
        -> execute_migration -> report
    """
    graph = StateGraph(MultiCloudOrchestratorState)

    graph.add_node(
        "discover_resources",
        traced_node(
            "mco.discover_resources",
            _AGENT,
        )(discover_resources),
    )
    graph.add_node(
        "normalize_inventory",
        traced_node(
            "mco.normalize_inventory",
            _AGENT,
        )(normalize_inventory),
    )
    graph.add_node(
        "compare_pricing",
        traced_node(
            "mco.compare_pricing",
            _AGENT,
        )(compare_pricing),
    )
    graph.add_node(
        "optimize_placement",
        traced_node(
            "mco.optimize_placement",
            _AGENT,
        )(optimize_placement),
    )
    graph.add_node(
        "execute_migration",
        traced_node(
            "mco.execute_migration",
            _AGENT,
        )(execute_migration),
    )
    graph.add_node(
        "report",
        traced_node(
            "mco.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("discover_resources")

    graph.add_conditional_edges(
        "discover_resources",
        _check_error,
        {"report": "report", "next": "normalize_inventory"},
    )
    graph.add_conditional_edges(
        "normalize_inventory",
        _check_error,
        {"report": "report", "next": "compare_pricing"},
    )
    graph.add_conditional_edges(
        "compare_pricing",
        _check_error,
        {"report": "report", "next": "optimize_placement"},
    )
    graph.add_conditional_edges(
        "optimize_placement",
        _check_error,
        {"report": "report", "next": "execute_migration"},
    )
    graph.add_edge("execute_migration", "report")
    graph.add_edge("report", END)

    return graph
