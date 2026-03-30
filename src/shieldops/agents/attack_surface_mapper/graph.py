"""LangGraph workflow for the Attack Surface Mapper Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.attack_surface_mapper.models import (
    AttackSurfaceMapperState,
)
from shieldops.agents.attack_surface_mapper.nodes import (
    assess_risk,
    classify_exposure,
    discover_assets,
    generate_report,
    map_attack_paths,
    recommend_remediation,
)
from shieldops.agents.tracing import traced_node

_AGENT = "attack_surface_mapper"


def _should_classify(
    state: AttackSurfaceMapperState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.discovered_assets:
        return "classify_exposure"
    return "generate_report"


def _should_map_paths(
    state: AttackSurfaceMapperState,
) -> str:
    """Route after risk assessment."""
    if state.max_risk_score > 50.0:
        return "map_attack_paths"
    return "recommend_remediation"


def create_attack_surface_mapper_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Attack Surface Mapper LangGraph.

    Workflow:
        discover_assets
          -> [has_assets?] -> classify_exposure
          -> assess_risk
          -> [high_risk?] -> map_attack_paths
          -> recommend_remediation
          -> generate_report
    """
    graph = StateGraph(AttackSurfaceMapperState)

    graph.add_node(
        "discover_assets",
        traced_node(
            f"{_AGENT}.discover_assets",
            _AGENT,
        )(discover_assets),
    )
    graph.add_node(
        "classify_exposure",
        traced_node(
            f"{_AGENT}.classify_exposure",
            _AGENT,
        )(classify_exposure),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "map_attack_paths",
        traced_node(
            f"{_AGENT}.map_attack_paths",
            _AGENT,
        )(map_attack_paths),
    )
    graph.add_node(
        "recommend_remediation",
        traced_node(
            f"{_AGENT}.recommend_remediation",
            _AGENT,
        )(recommend_remediation),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_assets")
    graph.add_conditional_edges(
        "discover_assets",
        _should_classify,
        {
            "classify_exposure": "classify_exposure",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("classify_exposure", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_map_paths,
        {
            "map_attack_paths": "map_attack_paths",
            "recommend_remediation": ("recommend_remediation"),
        },
    )
    graph.add_edge("map_attack_paths", "recommend_remediation")
    graph.add_edge("recommend_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
