"""AI Compliance Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AIComplianceState
from .nodes import (
    assess_requirements,
    classify_risk_levels,
    collect_inventory,
    evaluate_controls,
    generate_evidence,
    generate_report,
)
from .tools import AIComplianceToolkit


def build_graph(toolkit: AIComplianceToolkit):  # type: ignore[no-untyped-def]
    """Build the ai_compliance agent graph (linear sequence)."""
    return build_linear_graph(
        AIComplianceState,
        [
            ("collect_inventory", collect_inventory),
            ("classify_risk_levels", classify_risk_levels),
            ("assess_requirements", assess_requirements),
            ("evaluate_controls", evaluate_controls),
            ("generate_evidence", generate_evidence),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_ai_compliance_graph(
    inventory_client: Any | None = None,
    policy_client: Any | None = None,
    evidence_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the AI Compliance agent graph with dependencies."""
    toolkit = AIComplianceToolkit(
        inventory_client=inventory_client,
        policy_client=policy_client,
        evidence_store=evidence_store,
    )
    return build_graph(toolkit)
