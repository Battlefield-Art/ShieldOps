"""LangGraph workflow definition for the Threat Feed Manager Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_feed_manager.models import (
    ThreatFeedManagerState,
)
from shieldops.agents.threat_feed_manager.nodes import (
    deduplicate,
    enrich,
    ingest_feeds,
    normalize,
    report,
    score,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_feed_manager"


def _route_after_ingest(state: ThreatFeedManagerState) -> str:
    if state.error:
        return "report"
    return "normalize"


def _route_after_normalize(state: ThreatFeedManagerState) -> str:
    if state.error:
        return "report"
    return "deduplicate"


def _route_after_dedup(state: ThreatFeedManagerState) -> str:
    if state.error:
        return "report"
    return "score"


def _route_after_score(state: ThreatFeedManagerState) -> str:
    if state.error:
        return "report"
    return "enrich"


def _route_after_enrich(state: ThreatFeedManagerState) -> str:
    return "report"


def create_threat_feed_manager_graph() -> StateGraph:
    """Build the Threat Feed Manager LangGraph workflow.

    Workflow:
        ingest_feeds -> normalize -> deduplicate
        -> score -> enrich -> report -> END

    Error at any stage short-circuits to report.
    """
    graph = StateGraph(ThreatFeedManagerState)

    graph.add_node(
        "ingest_feeds",
        traced_node(f"{_AGENT}.ingest_feeds", _AGENT)(ingest_feeds),
    )
    graph.add_node(
        "normalize",
        traced_node(f"{_AGENT}.normalize", _AGENT)(normalize),
    )
    graph.add_node(
        "deduplicate",
        traced_node(f"{_AGENT}.deduplicate", _AGENT)(deduplicate),
    )
    graph.add_node(
        "score",
        traced_node(f"{_AGENT}.score", _AGENT)(score),
    )
    graph.add_node(
        "enrich",
        traced_node(f"{_AGENT}.enrich", _AGENT)(enrich),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("ingest_feeds")

    graph.add_conditional_edges(
        "ingest_feeds",
        _route_after_ingest,
        {"normalize": "normalize", "report": "report"},
    )
    graph.add_conditional_edges(
        "normalize",
        _route_after_normalize,
        {"deduplicate": "deduplicate", "report": "report"},
    )
    graph.add_conditional_edges(
        "deduplicate",
        _route_after_dedup,
        {"score": "score", "report": "report"},
    )
    graph.add_conditional_edges(
        "score",
        _route_after_score,
        {"enrich": "enrich", "report": "report"},
    )
    graph.add_edge("enrich", "report")
    graph.add_edge("report", END)

    return graph
