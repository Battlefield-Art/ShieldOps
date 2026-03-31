"""LangGraph workflow definition for the Security
Onboarding Engine Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_onboarding_engine.models import (
    SecurityOnboardingEngineState,
)
from shieldops.agents.security_onboarding_engine.nodes import (
    assess_risk_profile,
    generate_report,
    generate_requirements,
    intake_service,
    provision_controls,
    validate_onboarding,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_onboarding_engine"


def _should_validate(
    state: SecurityOnboardingEngineState,
) -> str:
    """Route after provisioning: validate if controls
    exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.controls_provisioned > 0:
        return "validate_onboarding"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Onboarding Engine LangGraph
    workflow.

    Workflow:
        intake_service -> assess_risk_profile
            -> generate_requirements -> provision_controls
            -> [controls? -> validate_onboarding]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityOnboardingEngineState)

    graph.add_node(
        "intake_service",
        traced_node(f"{_AGENT}.intake_service", _AGENT)(intake_service),
    )
    graph.add_node(
        "assess_risk_profile",
        traced_node(f"{_AGENT}.assess_risk_profile", _AGENT)(assess_risk_profile),
    )
    graph.add_node(
        "generate_requirements",
        traced_node(f"{_AGENT}.generate_requirements", _AGENT)(generate_requirements),
    )
    graph.add_node(
        "provision_controls",
        traced_node(f"{_AGENT}.provision_controls", _AGENT)(provision_controls),
    )
    graph.add_node(
        "validate_onboarding",
        traced_node(f"{_AGENT}.validate_onboarding", _AGENT)(validate_onboarding),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("intake_service")
    graph.add_edge("intake_service", "assess_risk_profile")
    graph.add_edge("assess_risk_profile", "generate_requirements")
    graph.add_edge("generate_requirements", "provision_controls")
    graph.add_conditional_edges(
        "provision_controls",
        _should_validate,
        {
            "validate_onboarding": "validate_onboarding",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_onboarding", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_onboarding_engine_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Onboarding Engine
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
