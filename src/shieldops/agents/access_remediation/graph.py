"""LangGraph workflow for the Access Remediation Agent."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AccessRemediationState
from .nodes import (
    audit_access,
    execute_changes,
    generate_report,
    identify_excess,
    plan_remediation,
    verify_access,
)


def build_graph():  # type: ignore[no-untyped-def]
    """Build the access_remediation agent graph (linear sequence)."""
    return build_linear_graph(
        AccessRemediationState,
        [
            ("audit_access", audit_access),
            ("identify_excess", identify_excess),
            ("plan_remediation", plan_remediation),
            ("execute_changes", execute_changes),
            ("verify_access", verify_access),
            ("generate_report", generate_report),
        ],
    )


def create_access_remediation_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create an Access Remediation graph."""
    return build_graph()
