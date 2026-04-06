"""Agent Governance Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AgentGovernanceState
from .nodes import (
    assess_capabilities,
    audit_compliance,
    discover_agents,
    enforce_boundaries,
    evaluate_escalations,
    generate_report,
)
from .tools import AgentGovernanceToolkit


def build_graph(toolkit: AgentGovernanceToolkit):  # type: ignore[no-untyped-def]
    """Build the agent_governance agent graph (linear sequence)."""
    return build_linear_graph(
        AgentGovernanceState,
        [
            ("discover_agents", discover_agents),
            ("assess_capabilities", assess_capabilities),
            ("enforce_boundaries", enforce_boundaries),
            ("evaluate_escalations", evaluate_escalations),
            ("audit_compliance", audit_compliance),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_agent_governance_graph(
    registry_client: Any | None = None,
    policy_client: Any | None = None,
    notification_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Agent Governance agent graph with dependencies."""
    toolkit = AgentGovernanceToolkit(
        registry_client=registry_client,
        policy_client=policy_client,
        notification_client=notification_client,
    )
    return build_graph(toolkit)
