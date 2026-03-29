"""LangGraph workflow for the Threat Feed Aggregator."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_feed_aggregator.models import (
    ThreatFeedAggregatorState,
)
from shieldops.agents.threat_feed_aggregator.nodes import (
    deduplicate,
    discover_feeds,
    ingest_indicators,
    normalize_data,
    report,
    score_relevance,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_feed_aggregator"


def _check_error(
    state: ThreatFeedAggregatorState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_threat_feed_aggregator_graph() -> StateGraph[ThreatFeedAggregatorState]:
    """Build the Threat Feed Aggregator workflow."""
    graph = StateGraph(ThreatFeedAggregatorState)

    graph.add_node(
        "discover_feeds",
        traced_node(
            "tfa.discover_feeds",
            _AGENT,
        )(discover_feeds),
    )
    graph.add_node(
        "ingest_indicators",
        traced_node(
            "tfa.ingest_indicators",
            _AGENT,
        )(ingest_indicators),
    )
    graph.add_node(
        "normalize_data",
        traced_node(
            "tfa.normalize_data",
            _AGENT,
        )(normalize_data),
    )
    graph.add_node(
        "deduplicate",
        traced_node(
            "tfa.deduplicate",
            _AGENT,
        )(deduplicate),
    )
    graph.add_node(
        "score_relevance",
        traced_node(
            "tfa.score_relevance",
            _AGENT,
        )(score_relevance),
    )
    graph.add_node(
        "report",
        traced_node(
            "tfa.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("discover_feeds")

    graph.add_conditional_edges(
        "discover_feeds",
        _check_error,
        {"report": "report", "next": "ingest_indicators"},
    )
    graph.add_conditional_edges(
        "ingest_indicators",
        _check_error,
        {"report": "report", "next": "normalize_data"},
    )
    graph.add_conditional_edges(
        "normalize_data",
        _check_error,
        {"report": "report", "next": "deduplicate"},
    )
    graph.add_conditional_edges(
        "deduplicate",
        _check_error,
        {"report": "report", "next": "score_relevance"},
    )
    graph.add_edge("score_relevance", "report")
    graph.add_edge("report", END)

    return graph
