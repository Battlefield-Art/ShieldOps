"""LangGraph workflow for Remediation Orchestrator."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.remediation_orchestrator.models import (
    RemediationOrchestratorState,
)
from shieldops.agents.remediation_orchestrator.nodes import (
    classify_and_route,
    create_tickets,
    dispatch_remediation,
    generate_report,
    receive_findings,
    track_progress,
)
from shieldops.agents.tracing import traced_node


def build_graph() -> StateGraph:
    """Build the Remediation Orchestrator LangGraph."""
    _a = "remediation_orchestrator"
    graph = StateGraph(RemediationOrchestratorState)

    graph.add_node(
        "receive_findings",
        traced_node("remorch.receive", _a)(receive_findings),
    )
    graph.add_node(
        "classify_and_route",
        traced_node("remorch.classify", _a)(classify_and_route),
    )
    graph.add_node(
        "create_tickets",
        traced_node("remorch.tickets", _a)(create_tickets),
    )
    graph.add_node(
        "dispatch_remediation",
        traced_node("remorch.dispatch", _a)(dispatch_remediation),
    )
    graph.add_node(
        "track_progress",
        traced_node("remorch.track", _a)(track_progress),
    )
    graph.add_node(
        "generate_report",
        traced_node("remorch.report", _a)(generate_report),
    )

    graph.set_entry_point("receive_findings")
    graph.add_edge("receive_findings", "classify_and_route")
    graph.add_edge("classify_and_route", "create_tickets")
    graph.add_edge("create_tickets", "dispatch_remediation")
    graph.add_edge("dispatch_remediation", "track_progress")
    graph.add_edge("track_progress", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_remediation_orchestrator_graph(
    **clients: object,
) -> StateGraph:
    """Factory for Remediation Orchestrator graph."""
    return build_graph()
