"""LangGraph workflow definition for the Threat Hunt
Orchestrator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_hunt_orchestrator.models import (
    ThreatHuntOrchestratorState,
)
from shieldops.agents.threat_hunt_orchestrator.nodes import (
    analyze_data,
    collect_evidence,
    document_hunt,
    generate_hypothesis,
    generate_report,
    validate_findings,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_hunt_orchestrator"


def _should_document(
    state: ThreatHuntOrchestratorState,
) -> str:
    """Route after validation: document if findings exist
    or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.total_findings > 0:
        return "document_hunt"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Hunt Orchestrator LangGraph
    workflow.

    Workflow:
        generate_hypothesis -> collect_evidence
            -> analyze_data -> validate_findings
            -> [findings? -> document_hunt]
            -> generate_report -> END
    """
    graph = StateGraph(ThreatHuntOrchestratorState)

    graph.add_node(
        "generate_hypothesis",
        traced_node(f"{_AGENT}.generate_hypothesis", _AGENT)(generate_hypothesis),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(f"{_AGENT}.collect_evidence", _AGENT)(collect_evidence),
    )
    graph.add_node(
        "analyze_data",
        traced_node(f"{_AGENT}.analyze_data", _AGENT)(analyze_data),
    )
    graph.add_node(
        "validate_findings",
        traced_node(f"{_AGENT}.validate_findings", _AGENT)(validate_findings),
    )
    graph.add_node(
        "document_hunt",
        traced_node(f"{_AGENT}.document_hunt", _AGENT)(document_hunt),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("generate_hypothesis")
    graph.add_edge("generate_hypothesis", "collect_evidence")
    graph.add_edge("collect_evidence", "analyze_data")
    graph.add_edge("analyze_data", "validate_findings")
    graph.add_conditional_edges(
        "validate_findings",
        _should_document,
        {
            "document_hunt": "document_hunt",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("document_hunt", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_threat_hunt_orchestrator_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Threat Hunt Orchestrator
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
