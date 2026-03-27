"""LangGraph workflow for the Access Remediation Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.access_remediation.models import (
    AccessRemediationState,
)
from shieldops.agents.access_remediation.nodes import (
    audit_access,
    execute_changes,
    generate_report,
    identify_excess,
    plan_remediation,
    verify_access,
)
from shieldops.agents.tracing import traced_node


def build_graph() -> StateGraph:
    """Build the Access Remediation LangGraph."""
    _a = "access_remediation"
    graph = StateGraph(AccessRemediationState)

    graph.add_node(
        "audit_access",
        traced_node("accrem.audit", _a)(audit_access),
    )
    graph.add_node(
        "identify_excess",
        traced_node("accrem.identify", _a)(identify_excess),
    )
    graph.add_node(
        "plan_remediation",
        traced_node("accrem.plan", _a)(plan_remediation),
    )
    graph.add_node(
        "execute_changes",
        traced_node("accrem.execute", _a)(execute_changes),
    )
    graph.add_node(
        "verify_access",
        traced_node("accrem.verify", _a)(verify_access),
    )
    graph.add_node(
        "generate_report",
        traced_node("accrem.report", _a)(generate_report),
    )

    graph.set_entry_point("audit_access")
    graph.add_edge("audit_access", "identify_excess")
    graph.add_edge("identify_excess", "plan_remediation")
    graph.add_edge("plan_remediation", "execute_changes")
    graph.add_edge("execute_changes", "verify_access")
    graph.add_edge("verify_access", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_access_remediation_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create an Access Remediation graph."""
    return build_graph()
