"""LangGraph workflow definition for the Toxic
Combination Detector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.toxic_combination_detector.models import (
    ToxicCombinationDetectorState,
)
from shieldops.agents.toxic_combination_detector.nodes import (
    analyze_combinations,
    assess_blast_radius,
    collect_permissions,
    detect_toxic,
    generate_report,
    recommend,
)
from shieldops.agents.tracing import traced_node

_AGENT = "toxic_combination_detector"


def _should_assess(
    state: ToxicCombinationDetectorState,
) -> str:
    """Route after detection: assess blast radius if
    toxic combos found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_toxic > 0:
        return "assess_blast_radius"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Toxic Combination Detector LangGraph
    workflow.

    Workflow:
        collect_permissions -> analyze_combinations
            -> detect_toxic
            -> [toxic? -> assess_blast_radius -> recommend]
            -> generate_report -> END
    """
    graph = StateGraph(ToxicCombinationDetectorState)

    graph.add_node(
        "collect_permissions",
        traced_node(f"{_AGENT}.collect_permissions", _AGENT)(collect_permissions),
    )
    graph.add_node(
        "analyze_combinations",
        traced_node(f"{_AGENT}.analyze_combinations", _AGENT)(analyze_combinations),
    )
    graph.add_node(
        "detect_toxic",
        traced_node(f"{_AGENT}.detect_toxic", _AGENT)(detect_toxic),
    )
    graph.add_node(
        "assess_blast_radius",
        traced_node(f"{_AGENT}.assess_blast_radius", _AGENT)(assess_blast_radius),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_permissions")
    graph.add_edge("collect_permissions", "analyze_combinations")
    graph.add_edge("analyze_combinations", "detect_toxic")
    graph.add_conditional_edges(
        "detect_toxic",
        _should_assess,
        {
            "assess_blast_radius": "assess_blast_radius",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_blast_radius", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_toxic_combination_detector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Toxic Combination Detector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
