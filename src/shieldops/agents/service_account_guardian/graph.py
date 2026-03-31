"""LangGraph workflow definition for the Service Account
Guardian Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.service_account_guardian.models import (
    ServiceAccountGuardianState,
)
from shieldops.agents.service_account_guardian.nodes import (
    assess_risk,
    audit_permissions,
    detect_orphans,
    discover_accounts,
    generate_report,
    remediate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "service_account_guardian"


def _should_remediate(
    state: ServiceAccountGuardianState,
) -> str:
    """Route after risk assessment: remediate if high-risk
    accounts exist or skip to report."""
    if state.error:
        return "generate_report"
    if state.high_risk_count > 0:
        return "remediate"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Service Account Guardian LangGraph
    workflow.

    Workflow:
        discover_accounts -> audit_permissions
            -> detect_orphans -> assess_risk
            -> [high_risk? -> remediate]
            -> generate_report -> END
    """
    graph = StateGraph(ServiceAccountGuardianState)

    graph.add_node(
        "discover_accounts",
        traced_node(f"{_AGENT}.discover_accounts", _AGENT)(discover_accounts),
    )
    graph.add_node(
        "audit_permissions",
        traced_node(f"{_AGENT}.audit_permissions", _AGENT)(audit_permissions),
    )
    graph.add_node(
        "detect_orphans",
        traced_node(f"{_AGENT}.detect_orphans", _AGENT)(detect_orphans),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "remediate",
        traced_node(f"{_AGENT}.remediate", _AGENT)(remediate),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_accounts")
    graph.add_edge("discover_accounts", "audit_permissions")
    graph.add_edge("audit_permissions", "detect_orphans")
    graph.add_edge("detect_orphans", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_remediate,
        {
            "remediate": "remediate",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_service_account_guardian_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Service Account Guardian
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
