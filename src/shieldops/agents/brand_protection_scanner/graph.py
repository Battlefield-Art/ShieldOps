"""Brand Protection Scanner Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.brand_protection_scanner.models import BrandProtectionScannerState
from shieldops.agents.brand_protection_scanner.nodes import (
    analyze_similarity,
    check_certificates,
    classify_threats,
    discover_domains,
    report,
    takedown,
)
from shieldops.agents.tracing import traced_node

_AGENT = "brand_protection_scanner"


def _check_error(state: BrandProtectionScannerState) -> str:
    return "report" if state.error else "next"


def create_brand_protection_scanner_graph() -> StateGraph:
    """Build the Brand Protection Scanner workflow."""
    graph = StateGraph(BrandProtectionScannerState)

    graph.add_node(
        "discover_domains",
        traced_node(f"{_AGENT}.discover_domains", _AGENT)(discover_domains),
    )
    graph.add_node(
        "analyze_similarity",
        traced_node(f"{_AGENT}.analyze_similarity", _AGENT)(analyze_similarity),
    )
    graph.add_node(
        "check_certificates",
        traced_node(f"{_AGENT}.check_certificates", _AGENT)(check_certificates),
    )
    graph.add_node(
        "classify_threats",
        traced_node(f"{_AGENT}.classify_threats", _AGENT)(classify_threats),
    )
    graph.add_node(
        "takedown",
        traced_node(f"{_AGENT}.takedown", _AGENT)(takedown),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_domains")

    graph.add_conditional_edges(
        "discover_domains",
        _check_error,
        {"next": "analyze_similarity", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_similarity",
        _check_error,
        {"next": "check_certificates", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_certificates",
        _check_error,
        {"next": "classify_threats", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_threats",
        _check_error,
        {"next": "takedown", "report": "report"},
    )
    graph.add_edge("takedown", "report")
    graph.add_edge("report", END)

    return graph
