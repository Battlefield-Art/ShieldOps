"""Health Check Orchestrator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.health_check_orchestrator.models import (
    HealthCheckOrchestratorState,
)
from shieldops.agents.health_check_orchestrator.nodes import (
    assess_health,
    correlate_issues,
    discover_services,
    probe_endpoints,
    report,
    trigger_remediation,
)
from shieldops.agents.tracing import traced_node

_AGENT = "health_check_orchestrator"


def _check_error(
    state: HealthCheckOrchestratorState,
) -> str:
    return "report" if state.error else "next"


def create_health_check_orchestrator_graph() -> StateGraph:
    """Build the Health Check Orchestrator."""
    graph = StateGraph(HealthCheckOrchestratorState)

    graph.add_node(
        "discover_services",
        traced_node("hco.discover_services", _AGENT)(discover_services),
    )
    graph.add_node(
        "probe_endpoints",
        traced_node("hco.probe_endpoints", _AGENT)(probe_endpoints),
    )
    graph.add_node(
        "assess_health",
        traced_node("hco.assess_health", _AGENT)(assess_health),
    )
    graph.add_node(
        "correlate_issues",
        traced_node("hco.correlate_issues", _AGENT)(correlate_issues),
    )
    graph.add_node(
        "trigger_remediation",
        traced_node("hco.trigger_remediation", _AGENT)(trigger_remediation),
    )
    graph.add_node(
        "report",
        traced_node("hco.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_services")

    graph.add_conditional_edges(
        "discover_services",
        _check_error,
        {
            "report": "report",
            "next": "probe_endpoints",
        },
    )
    graph.add_conditional_edges(
        "probe_endpoints",
        _check_error,
        {
            "report": "report",
            "next": "assess_health",
        },
    )
    graph.add_conditional_edges(
        "assess_health",
        _check_error,
        {
            "report": "report",
            "next": "correlate_issues",
        },
    )
    graph.add_conditional_edges(
        "correlate_issues",
        _check_error,
        {
            "report": "report",
            "next": "trigger_remediation",
        },
    )
    graph.add_edge("trigger_remediation", "report")
    graph.add_edge("report", END)

    return graph
