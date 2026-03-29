"""MFA Compliance Checker Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.mfa_compliance_checker.models import MfaComplianceCheckerState
from shieldops.agents.mfa_compliance_checker.nodes import (
    check_mfa_status,
    classify_risk,
    discover_accounts,
    enforce_policy,
    report,
    report_gaps,
)
from shieldops.agents.tracing import traced_node

_AGENT = "mfa_compliance_checker"


def _check_error(state: MfaComplianceCheckerState) -> str:
    return "report" if state.error else "next"


def create_mfa_compliance_checker_graph() -> StateGraph:
    """Build the MFA Compliance Checker workflow."""
    graph = StateGraph(MfaComplianceCheckerState)

    graph.add_node(
        "discover_accounts",
        traced_node(f"{_AGENT}.discover_accounts", _AGENT)(discover_accounts),
    )
    graph.add_node(
        "check_mfa_status",
        traced_node(f"{_AGENT}.check_mfa_status", _AGENT)(check_mfa_status),
    )
    graph.add_node(
        "classify_risk",
        traced_node(f"{_AGENT}.classify_risk", _AGENT)(classify_risk),
    )
    graph.add_node(
        "enforce_policy",
        traced_node(f"{_AGENT}.enforce_policy", _AGENT)(enforce_policy),
    )
    graph.add_node(
        "report_gaps",
        traced_node(f"{_AGENT}.report_gaps", _AGENT)(report_gaps),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_accounts")

    graph.add_conditional_edges(
        "discover_accounts",
        _check_error,
        {"next": "check_mfa_status", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_mfa_status",
        _check_error,
        {"next": "classify_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_risk",
        _check_error,
        {"next": "enforce_policy", "report": "report"},
    )
    graph.add_conditional_edges(
        "enforce_policy",
        _check_error,
        {"next": "report_gaps", "report": "report"},
    )
    graph.add_edge("report_gaps", "report")
    graph.add_edge("report", END)

    return graph
