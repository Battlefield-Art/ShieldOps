"""LangGraph workflow for Remediation Orchestrator."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import RemediationOrchestratorState
from .nodes import (
    classify_and_route,
    create_tickets,
    dispatch_remediation,
    generate_report,
    receive_findings,
    track_progress,
)


def build_graph():  # type: ignore[no-untyped-def]
    """Build the remediation_orchestrator agent graph (linear sequence)."""
    return build_linear_graph(
        RemediationOrchestratorState,
        [
            ("receive_findings", receive_findings),
            ("classify_and_route", classify_and_route),
            ("create_tickets", create_tickets),
            ("dispatch_remediation", dispatch_remediation),
            ("track_progress", track_progress),
            ("generate_report", generate_report),
        ],
    )


def create_remediation_orchestrator_graph(
    **clients: object,
) -> StateGraph:
    """Factory for Remediation Orchestrator graph."""
    return build_graph()
