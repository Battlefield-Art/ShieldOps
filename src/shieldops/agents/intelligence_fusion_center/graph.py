"""LangGraph workflow for the Intelligence Fusion Center."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.intelligence_fusion_center.models import (
    IntelligenceFusionCenterState,
)
from shieldops.agents.intelligence_fusion_center.nodes import (
    assess_threats,
    collect_feeds,
    correlate_threats,
    fuse_intelligence,
    generate_assessment,
    generate_report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "intelligence_fusion_center"


def should_generate_assessment(
    state: IntelligenceFusionCenterState,
) -> str:
    """Route: generate assessment or skip to report.

    Skips assessment generation if no actionable threats
    were found or if an error occurred.
    """
    if state.error:
        return END
    if state.actionable_count > 0:
        return "generate_assessment"
    if state.threat_assessments:
        return "generate_assessment"
    return "generate_report"


def create_intelligence_fusion_center_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Intelligence Fusion Center LangGraph workflow.

    Workflow:
        collect_feeds
        -> correlate_threats
        -> fuse_intelligence
        -> assess_threats
        -> [conditional: generate_assessment OR generate_report]
        -> generate_report
        -> END
    """
    graph = StateGraph(IntelligenceFusionCenterState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "collect_feeds",
        traced_node(
            f"{_AGENT}.collect_feeds",
            _AGENT,
        )(collect_feeds),
    )
    graph.add_node(
        "correlate_threats",
        traced_node(
            f"{_AGENT}.correlate_threats",
            _AGENT,
        )(correlate_threats),
    )
    graph.add_node(
        "fuse_intelligence",
        traced_node(
            f"{_AGENT}.fuse_intelligence",
            _AGENT,
        )(fuse_intelligence),
    )
    graph.add_node(
        "assess_threats",
        traced_node(
            f"{_AGENT}.assess_threats",
            _AGENT,
        )(assess_threats),
    )
    graph.add_node(
        "generate_assessment",
        traced_node(
            f"{_AGENT}.generate_assessment",
            _AGENT,
        )(generate_assessment),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_feeds")
    graph.add_edge("collect_feeds", "correlate_threats")
    graph.add_edge("correlate_threats", "fuse_intelligence")
    graph.add_edge("fuse_intelligence", "assess_threats")
    graph.add_conditional_edges(
        "assess_threats",
        should_generate_assessment,
        {
            "generate_assessment": "generate_assessment",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("generate_assessment", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
