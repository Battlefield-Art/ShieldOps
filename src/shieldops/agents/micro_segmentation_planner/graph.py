"""Micro Segmentation Planner Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.micro_segmentation_planner.models import MicroSegmentationPlannerState
from shieldops.agents.micro_segmentation_planner.nodes import (
    define_policies,
    identify_segments,
    map_traffic,
    report,
    simulate,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "micro_segmentation_planner"


def _check_error(state: MicroSegmentationPlannerState) -> str:
    return "report" if state.error else "next"


def create_micro_segmentation_planner_graph() -> StateGraph:
    """Build the Micro Segmentation Planner workflow."""
    graph = StateGraph(MicroSegmentationPlannerState)

    graph.add_node(
        "map_traffic",
        traced_node(f"{_AGENT}.map_traffic", _AGENT)(map_traffic),
    )
    graph.add_node(
        "identify_segments",
        traced_node(f"{_AGENT}.identify_segments", _AGENT)(identify_segments),
    )
    graph.add_node(
        "define_policies",
        traced_node(f"{_AGENT}.define_policies", _AGENT)(define_policies),
    )
    graph.add_node(
        "simulate",
        traced_node(f"{_AGENT}.simulate", _AGENT)(simulate),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("map_traffic")

    graph.add_conditional_edges(
        "map_traffic",
        _check_error,
        {"next": "identify_segments", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_segments",
        _check_error,
        {"next": "define_policies", "report": "report"},
    )
    graph.add_conditional_edges(
        "define_policies",
        _check_error,
        {"next": "simulate", "report": "report"},
    )
    graph.add_conditional_edges(
        "simulate",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
