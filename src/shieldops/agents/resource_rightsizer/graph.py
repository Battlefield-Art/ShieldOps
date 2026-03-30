"""Resource Rightsizer — LangGraph definition."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import ResourceRightsizerState
from .nodes import (
    analyze_patterns,
    collect_utilization,
    identify_overprovisioned,
    recommend_sizes,
    report,
    validate_impact,
)

logger = structlog.get_logger()

_AGENT = "resource_rightsizer"


def _check_error(
    state: ResourceRightsizerState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_resource_rightsizer_graph() -> StateGraph[ResourceRightsizerState]:
    """Build the Resource Rightsizer graph.

    Flow:
        collect_utilization -> analyze_patterns
        -> identify_overprovisioned -> recommend_sizes
        -> validate_impact -> report
    """
    graph = StateGraph(ResourceRightsizerState)

    graph.add_node(
        "collect_utilization",
        traced_node(
            "rr.collect_utilization",
            _AGENT,
        )(collect_utilization),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node(
            "rr.analyze_patterns",
            _AGENT,
        )(analyze_patterns),
    )
    graph.add_node(
        "identify_overprovisioned",
        traced_node(
            "rr.identify_overprovisioned",
            _AGENT,
        )(identify_overprovisioned),
    )
    graph.add_node(
        "recommend_sizes",
        traced_node(
            "rr.recommend_sizes",
            _AGENT,
        )(recommend_sizes),
    )
    graph.add_node(
        "validate_impact",
        traced_node(
            "rr.validate_impact",
            _AGENT,
        )(validate_impact),
    )
    graph.add_node(
        "report",
        traced_node(
            "rr.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("collect_utilization")

    graph.add_conditional_edges(
        "collect_utilization",
        _check_error,
        {"report": "report", "next": "analyze_patterns"},
    )
    graph.add_conditional_edges(
        "analyze_patterns",
        _check_error,
        {
            "report": "report",
            "next": "identify_overprovisioned",
        },
    )
    graph.add_conditional_edges(
        "identify_overprovisioned",
        _check_error,
        {"report": "report", "next": "recommend_sizes"},
    )
    graph.add_conditional_edges(
        "recommend_sizes",
        _check_error,
        {"report": "report", "next": "validate_impact"},
    )
    graph.add_edge("validate_impact", "report")
    graph.add_edge("report", END)

    return graph
