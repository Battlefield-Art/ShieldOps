"""LangGraph workflow for the Threat Hunt Automation."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_hunt_automation.models import (
    ThreatHuntAutomationState,
)
from shieldops.agents.threat_hunt_automation.nodes import (
    analyze_results,
    design_queries,
    document_findings,
    execute_hunts,
    generate_hypotheses,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_hunt_automation"


def _check_error(
    state: ThreatHuntAutomationState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_threat_hunt_automation_graph() -> StateGraph[ThreatHuntAutomationState]:
    """Build the Threat Hunt Automation workflow."""
    graph = StateGraph(ThreatHuntAutomationState)

    graph.add_node(
        "generate_hypotheses",
        traced_node(
            "tha.generate_hypotheses",
            _AGENT,
        )(generate_hypotheses),
    )
    graph.add_node(
        "design_queries",
        traced_node(
            "tha.design_queries",
            _AGENT,
        )(design_queries),
    )
    graph.add_node(
        "execute_hunts",
        traced_node(
            "tha.execute_hunts",
            _AGENT,
        )(execute_hunts),
    )
    graph.add_node(
        "analyze_results",
        traced_node(
            "tha.analyze_results",
            _AGENT,
        )(analyze_results),
    )
    graph.add_node(
        "document_findings",
        traced_node(
            "tha.document_findings",
            _AGENT,
        )(document_findings),
    )
    graph.add_node(
        "report",
        traced_node(
            "tha.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("generate_hypotheses")

    graph.add_conditional_edges(
        "generate_hypotheses",
        _check_error,
        {
            "report": "report",
            "next": "design_queries",
        },
    )
    graph.add_conditional_edges(
        "design_queries",
        _check_error,
        {
            "report": "report",
            "next": "execute_hunts",
        },
    )
    graph.add_conditional_edges(
        "execute_hunts",
        _check_error,
        {
            "report": "report",
            "next": "analyze_results",
        },
    )
    graph.add_conditional_edges(
        "analyze_results",
        _check_error,
        {
            "report": "report",
            "next": "document_findings",
        },
    )
    graph.add_edge("document_findings", "report")
    graph.add_edge("report", END)

    return graph
