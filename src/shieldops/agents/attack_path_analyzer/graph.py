"""Attack Path Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.attack_path_analyzer.models import AttackPathAnalyzerState
from shieldops.agents.attack_path_analyzer.nodes import (
    calculate_risk,
    discover_assets,
    identify_paths,
    map_relationships,
    recommend_mitigations,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "attack_path_analyzer"


def _check_error(state: AttackPathAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_attack_path_analyzer_graph() -> StateGraph:
    """Build the Attack Path Analyzer workflow."""
    graph = StateGraph(AttackPathAnalyzerState)

    graph.add_node(
        "discover_assets",
        traced_node(f"{_AGENT}.discover_assets", _AGENT)(discover_assets),
    )
    graph.add_node(
        "map_relationships",
        traced_node(f"{_AGENT}.map_relationships", _AGENT)(map_relationships),
    )
    graph.add_node(
        "identify_paths",
        traced_node(f"{_AGENT}.identify_paths", _AGENT)(identify_paths),
    )
    graph.add_node(
        "calculate_risk",
        traced_node(f"{_AGENT}.calculate_risk", _AGENT)(calculate_risk),
    )
    graph.add_node(
        "recommend_mitigations",
        traced_node(f"{_AGENT}.recommend_mitigations", _AGENT)(recommend_mitigations),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_assets")

    graph.add_conditional_edges(
        "discover_assets",
        _check_error,
        {"next": "map_relationships", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_relationships",
        _check_error,
        {"next": "identify_paths", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_paths",
        _check_error,
        {"next": "calculate_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "calculate_risk",
        _check_error,
        {"next": "recommend_mitigations", "report": "report"},
    )
    graph.add_edge("recommend_mitigations", "report")
    graph.add_edge("report", END)

    return graph
