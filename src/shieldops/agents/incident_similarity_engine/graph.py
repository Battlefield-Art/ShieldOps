"""Incident Similarity Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_similarity_engine.models import IncidentSimilarityEngineState
from shieldops.agents.incident_similarity_engine.nodes import (
    compute_similarity,
    extract_features,
    ingest_incident,
    rank_matches,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_similarity_engine"


def _check_error(state: IncidentSimilarityEngineState) -> str:
    return "report" if state.error else "next"


def create_incident_similarity_engine_graph() -> StateGraph:
    """Build the Incident Similarity Engine workflow."""
    graph = StateGraph(IncidentSimilarityEngineState)

    graph.add_node(
        "ingest_incident",
        traced_node(f"{_AGENT}.ingest_incident", _AGENT)(ingest_incident),
    )
    graph.add_node(
        "extract_features",
        traced_node(f"{_AGENT}.extract_features", _AGENT)(extract_features),
    )
    graph.add_node(
        "compute_similarity",
        traced_node(f"{_AGENT}.compute_similarity", _AGENT)(compute_similarity),
    )
    graph.add_node(
        "rank_matches",
        traced_node(f"{_AGENT}.rank_matches", _AGENT)(rank_matches),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("ingest_incident")

    graph.add_conditional_edges(
        "ingest_incident",
        _check_error,
        {"next": "extract_features", "report": "report"},
    )
    graph.add_conditional_edges(
        "extract_features",
        _check_error,
        {"next": "compute_similarity", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_similarity",
        _check_error,
        {"next": "rank_matches", "report": "report"},
    )
    graph.add_conditional_edges(
        "rank_matches",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
