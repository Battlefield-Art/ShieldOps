"""LangGraph workflow definition for the Access
Certification Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.access_certification_engine.models import (
    AccessCertificationEngineState,
)
from shieldops.agents.access_certification_engine.nodes import (
    analyze_usage,
    collect_entitlements,
    generate_report,
    generate_reviews,
    identify_excess,
    process_decisions,
)
from shieldops.agents.tracing import traced_node

_AGENT = "access_certification_engine"


def _should_review(
    state: AccessCertificationEngineState,
) -> str:
    """Route after excess identification: generate reviews
    if excess found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.excess_found > 0:
        return "generate_reviews"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Access Certification Engine LangGraph
    workflow.

    Workflow:
        collect_entitlements -> analyze_usage
            -> identify_excess
            -> [excess? -> generate_reviews
               -> process_decisions]
            -> generate_report -> END
    """
    graph = StateGraph(AccessCertificationEngineState)

    graph.add_node(
        "collect_entitlements",
        traced_node(f"{_AGENT}.collect_entitlements", _AGENT)(collect_entitlements),
    )
    graph.add_node(
        "analyze_usage",
        traced_node(f"{_AGENT}.analyze_usage", _AGENT)(analyze_usage),
    )
    graph.add_node(
        "identify_excess",
        traced_node(f"{_AGENT}.identify_excess", _AGENT)(identify_excess),
    )
    graph.add_node(
        "generate_reviews",
        traced_node(f"{_AGENT}.generate_reviews", _AGENT)(generate_reviews),
    )
    graph.add_node(
        "process_decisions",
        traced_node(f"{_AGENT}.process_decisions", _AGENT)(process_decisions),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_entitlements")
    graph.add_edge("collect_entitlements", "analyze_usage")
    graph.add_edge("analyze_usage", "identify_excess")
    graph.add_conditional_edges(
        "identify_excess",
        _should_review,
        {
            "generate_reviews": "generate_reviews",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_reviews", "process_decisions")
    graph.add_edge("process_decisions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_access_certification_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Access Certification Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
