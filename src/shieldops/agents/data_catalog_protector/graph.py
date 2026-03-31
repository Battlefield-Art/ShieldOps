"""LangGraph workflow definition for the Data Catalog
Protector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.data_catalog_protector.models import (
    DataCatalogProtectorState,
)
from shieldops.agents.data_catalog_protector.nodes import (
    classify_sensitivity,
    detect_violations,
    enforce_policies,
    generate_report,
    map_access,
    scan_catalogs,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_catalog_protector"


def _should_enforce(
    state: DataCatalogProtectorState,
) -> str:
    """Route after violation detection: enforce if
    violations found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.violations_found > 0:
        return "enforce_policies"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Catalog Protector LangGraph
    workflow.

    Workflow:
        scan_catalogs -> classify_sensitivity
            -> map_access -> detect_violations
            -> [violations? -> enforce_policies]
            -> generate_report -> END
    """
    graph = StateGraph(DataCatalogProtectorState)

    graph.add_node(
        "scan_catalogs",
        traced_node(f"{_AGENT}.scan_catalogs", _AGENT)(scan_catalogs),
    )
    graph.add_node(
        "classify_sensitivity",
        traced_node(f"{_AGENT}.classify_sensitivity", _AGENT)(classify_sensitivity),
    )
    graph.add_node(
        "map_access",
        traced_node(f"{_AGENT}.map_access", _AGENT)(map_access),
    )
    graph.add_node(
        "detect_violations",
        traced_node(f"{_AGENT}.detect_violations", _AGENT)(detect_violations),
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
    graph.set_entry_point("scan_catalogs")
    graph.add_edge("scan_catalogs", "classify_sensitivity")
    graph.add_edge("classify_sensitivity", "map_access")
    graph.add_edge("map_access", "detect_violations")
    graph.add_conditional_edges(
        "detect_violations",
        _should_enforce,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_data_catalog_protector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Data Catalog Protector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
