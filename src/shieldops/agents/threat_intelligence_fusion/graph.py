"""LangGraph workflow for the Threat Intelligence Fusion Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_intelligence_fusion.models import (
    ThreatIntelligenceFusionState,
)
from shieldops.agents.threat_intelligence_fusion.nodes import (
    collect_feeds,
    correlate_indicators,
    enrich_context,
    generate_report,
    normalize_iocs,
    score_threats,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_intelligence_fusion"


def _should_normalize(
    state: ThreatIntelligenceFusionState,
) -> str:
    """Route after feed collection based on results."""
    if state.error:
        return "generate_report"
    if state.collected_feeds:
        return "normalize_iocs"
    return "generate_report"


def _should_enrich(
    state: ThreatIntelligenceFusionState,
) -> str:
    """Route after correlation."""
    if state.campaign_count > 0:
        return "enrich_context"
    return "enrich_context"


def create_threat_intelligence_fusion_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Intelligence Fusion LangGraph.

    Workflow:
        collect_feeds
          -> [has_feeds?] -> normalize_iocs
          -> correlate_indicators
          -> enrich_context
          -> score_threats
          -> generate_report
    """
    graph = StateGraph(ThreatIntelligenceFusionState)

    graph.add_node(
        "collect_feeds",
        traced_node(
            f"{_AGENT}.collect_feeds",
            _AGENT,
        )(collect_feeds),
    )
    graph.add_node(
        "normalize_iocs",
        traced_node(
            f"{_AGENT}.normalize_iocs",
            _AGENT,
        )(normalize_iocs),
    )
    graph.add_node(
        "correlate_indicators",
        traced_node(
            f"{_AGENT}.correlate_indicators",
            _AGENT,
        )(correlate_indicators),
    )
    graph.add_node(
        "enrich_context",
        traced_node(
            f"{_AGENT}.enrich_context",
            _AGENT,
        )(enrich_context),
    )
    graph.add_node(
        "score_threats",
        traced_node(
            f"{_AGENT}.score_threats",
            _AGENT,
        )(score_threats),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_feeds")
    graph.add_conditional_edges(
        "collect_feeds",
        _should_normalize,
        {
            "normalize_iocs": "normalize_iocs",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("normalize_iocs", "correlate_indicators")
    graph.add_conditional_edges(
        "correlate_indicators",
        _should_enrich,
        {
            "enrich_context": "enrich_context",
        },
    )
    graph.add_edge("enrich_context", "score_threats")
    graph.add_edge("score_threats", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
