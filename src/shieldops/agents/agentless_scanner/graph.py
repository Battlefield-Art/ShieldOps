"""LangGraph workflow definition for the Agentless
Scanner Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.agentless_scanner.models import (
    AgentlessScannerState,
)
from shieldops.agents.agentless_scanner.nodes import (
    analyze_exposure,
    check_vulns,
    discover_assets,
    generate_report,
    prioritize,
    scan_config,
)
from shieldops.agents.tracing import traced_node

_AGENT = "agentless_scanner"


def _should_prioritize(
    state: AgentlessScannerState,
) -> str:
    """Route after exposure analysis: prioritize if
    findings exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    all_findings = len(state.config_findings) + len(state.vuln_findings)
    if all_findings > 0:
        return "prioritize"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Agentless Scanner LangGraph workflow.

    Workflow:
        discover_assets -> scan_config -> check_vulns
            -> analyze_exposure
            -> [findings? -> prioritize]
            -> generate_report -> END
    """
    graph = StateGraph(AgentlessScannerState)

    graph.add_node(
        "discover_assets",
        traced_node(f"{_AGENT}.discover_assets", _AGENT)(discover_assets),
    )
    graph.add_node(
        "scan_config",
        traced_node(f"{_AGENT}.scan_config", _AGENT)(scan_config),
    )
    graph.add_node(
        "check_vulns",
        traced_node(f"{_AGENT}.check_vulns", _AGENT)(check_vulns),
    )
    graph.add_node(
        "analyze_exposure",
        traced_node(f"{_AGENT}.analyze_exposure", _AGENT)(analyze_exposure),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_assets")
    graph.add_edge("discover_assets", "scan_config")
    graph.add_edge("scan_config", "check_vulns")
    graph.add_edge("check_vulns", "analyze_exposure")
    graph.add_conditional_edges(
        "analyze_exposure",
        _should_prioritize,
        {
            "prioritize": "prioritize",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_agentless_scanner_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Agentless Scanner graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
