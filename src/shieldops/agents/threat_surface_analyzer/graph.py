"""LangGraph workflow for the Threat Surface Analyzer."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.threat_surface_analyzer.models import (
    ThreatSurfaceAnalyzerState,
)
from shieldops.agents.threat_surface_analyzer.nodes import (
    assess_risks,
    discover_assets,
    generate_report,
    map_exposure,
    prioritize_threats,
    recommend_mitigations,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "threat_surface_analyzer"


def should_map_exposure(
    state: ThreatSurfaceAnalyzerState,
) -> str:
    """Route: map exposures or skip to report if no assets found."""
    if state.error:
        return "generate_report"
    if state.assets:
        return "map_exposure"
    return "generate_report"


def should_recommend_mitigations(
    state: ThreatSurfaceAnalyzerState,
) -> str:
    """Route: recommend mitigations if critical/high risks exist."""
    if state.error:
        return "generate_report"
    if state.critical_count > 0 or state.high_count > 0:
        return "recommend_mitigations"
    return "generate_report"


def create_threat_surface_analyzer_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Threat Surface Analyzer LangGraph workflow.

    Workflow:
        discover_assets
        -> [has_assets? -> map_exposure -> assess_risks -> prioritize_threats]
        -> [critical/high? -> recommend_mitigations]
        -> generate_report
        -> END
    """
    graph = StateGraph(ThreatSurfaceAnalyzerState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "discover_assets",
        traced_node(
            f"{_AGENT}.discover_assets",
            _AGENT,
        )(discover_assets),
    )
    graph.add_node(
        "map_exposure",
        traced_node(
            f"{_AGENT}.map_exposure",
            _AGENT,
        )(map_exposure),
    )
    graph.add_node(
        "assess_risks",
        traced_node(
            f"{_AGENT}.assess_risks",
            _AGENT,
        )(assess_risks),
    )
    graph.add_node(
        "prioritize_threats",
        traced_node(
            f"{_AGENT}.prioritize_threats",
            _AGENT,
        )(prioritize_threats),
    )
    graph.add_node(
        "recommend_mitigations",
        traced_node(
            f"{_AGENT}.recommend_mitigations",
            _AGENT,
        )(recommend_mitigations),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("discover_assets")
    graph.add_conditional_edges(
        "discover_assets",
        should_map_exposure,
        {
            "map_exposure": "map_exposure",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("map_exposure", "assess_risks")
    graph.add_edge("assess_risks", "prioritize_threats")
    graph.add_conditional_edges(
        "prioritize_threats",
        should_recommend_mitigations,
        {
            "recommend_mitigations": "recommend_mitigations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_mitigations", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
