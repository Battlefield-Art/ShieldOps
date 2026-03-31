"""LangGraph workflow definition for the Policy
Compliance Enforcer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.policy_compliance_enforcer.models import (
    PolicyComplianceEnforcerState,
)
from shieldops.agents.policy_compliance_enforcer.nodes import (
    audit_log,
    check_compliance,
    enforce_decision,
    evaluate_request,
    generate_report,
    load_policies,
)
from shieldops.agents.tracing import traced_node

_AGENT = "policy_compliance_enforcer"


def _should_check_compliance(
    state: PolicyComplianceEnforcerState,
) -> str:
    """Route after evaluation: check compliance if
    violations exist, otherwise skip to enforce."""
    if state.error:
        return "generate_report"
    if state.violation_count > 0:
        return "check_compliance"
    return "enforce_decision"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Policy Compliance Enforcer LangGraph
    workflow.

    Workflow:
        load_policies -> evaluate_request
            -> [violations? -> check_compliance]
            -> enforce_decision -> audit_log
            -> generate_report -> END
    """
    graph = StateGraph(PolicyComplianceEnforcerState)

    graph.add_node(
        "load_policies",
        traced_node(f"{_AGENT}.load_policies", _AGENT)(load_policies),
    )
    graph.add_node(
        "evaluate_request",
        traced_node(f"{_AGENT}.evaluate_request", _AGENT)(evaluate_request),
    )
    graph.add_node(
        "check_compliance",
        traced_node(f"{_AGENT}.check_compliance", _AGENT)(check_compliance),
    )
    graph.add_node(
        "enforce_decision",
        traced_node(f"{_AGENT}.enforce_decision", _AGENT)(enforce_decision),
    )
    graph.add_node(
        "audit_log",
        traced_node(f"{_AGENT}.audit_log", _AGENT)(audit_log),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("load_policies")
    graph.add_edge("load_policies", "evaluate_request")
    graph.add_conditional_edges(
        "evaluate_request",
        _should_check_compliance,
        {
            "check_compliance": "check_compliance",
            "enforce_decision": "enforce_decision",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("check_compliance", "enforce_decision")
    graph.add_edge("enforce_decision", "audit_log")
    graph.add_edge("audit_log", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_policy_compliance_enforcer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Policy Compliance Enforcer
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
