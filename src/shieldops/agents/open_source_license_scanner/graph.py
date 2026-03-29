"""Open Source License Scanner Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.open_source_license_scanner.models import OpenSourceLicenseScannerState
from shieldops.agents.open_source_license_scanner.nodes import (
    check_compatibility,
    discover_deps,
    flag_violations,
    identify_licenses,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "open_source_license_scanner"


def _check_error(state: OpenSourceLicenseScannerState) -> str:
    return "report" if state.error else "next"


def create_open_source_license_scanner_graph() -> StateGraph:
    """Build the Open Source License Scanner workflow."""
    graph = StateGraph(OpenSourceLicenseScannerState)

    graph.add_node(
        "discover_deps",
        traced_node(f"{_AGENT}.discover_deps", _AGENT)(discover_deps),
    )
    graph.add_node(
        "identify_licenses",
        traced_node(f"{_AGENT}.identify_licenses", _AGENT)(identify_licenses),
    )
    graph.add_node(
        "check_compatibility",
        traced_node(f"{_AGENT}.check_compatibility", _AGENT)(check_compatibility),
    )
    graph.add_node(
        "flag_violations",
        traced_node(f"{_AGENT}.flag_violations", _AGENT)(flag_violations),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_deps")

    graph.add_conditional_edges(
        "discover_deps",
        _check_error,
        {"next": "identify_licenses", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_licenses",
        _check_error,
        {"next": "check_compatibility", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_compatibility",
        _check_error,
        {"next": "flag_violations", "report": "report"},
    )
    graph.add_conditional_edges(
        "flag_violations",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
