"""SBOM Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.sbom_analyzer.models import SbomAnalyzerState
from shieldops.agents.sbom_analyzer.nodes import (
    assess_risk,
    check_licenses,
    match_cves,
    parse_sbom,
    prioritize,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "sbom_analyzer"


def _check_error(state: SbomAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_sbom_analyzer_graph() -> StateGraph:
    """Build the SBOM Analyzer workflow."""
    graph = StateGraph(SbomAnalyzerState)

    graph.add_node(
        "parse_sbom",
        traced_node(f"{_AGENT}.parse_sbom", _AGENT)(parse_sbom),
    )
    graph.add_node(
        "match_cves",
        traced_node(f"{_AGENT}.match_cves", _AGENT)(match_cves),
    )
    graph.add_node(
        "check_licenses",
        traced_node(f"{_AGENT}.check_licenses", _AGENT)(check_licenses),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("parse_sbom")

    graph.add_conditional_edges(
        "parse_sbom",
        _check_error,
        {"next": "match_cves", "report": "report"},
    )
    graph.add_conditional_edges(
        "match_cves",
        _check_error,
        {"next": "check_licenses", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_licenses",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_risk",
        _check_error,
        {"next": "prioritize", "report": "report"},
    )
    graph.add_edge("prioritize", "report")
    graph.add_edge("report", END)

    return graph
