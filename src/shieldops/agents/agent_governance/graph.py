"""Agent Governance Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(toolkit: AgentGovernanceToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Agent Governance agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_agents(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_capabilities(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_boundaries(_to_dict(state), toolkit)

    async def _escalate(state: Any) -> dict[str, Any]:
        return await evaluate_escalations(_to_dict(state), toolkit)

    async def _audit(state: Any) -> dict[str, Any]:
        return await audit_compliance(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(AgentGovernanceState)
    graph.add_node("discover_agents", _discover)
    graph.add_node("assess_capabilities", _assess)
    graph.add_node("enforce_boundaries", _enforce)
    graph.add_node("evaluate_escalations", _escalate)
    graph.add_node("audit_compliance", _audit)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_agents")
    graph.add_edge("discover_agents", "assess_capabilities")
    graph.add_edge("assess_capabilities", "enforce_boundaries")
    graph.add_edge("enforce_boundaries", "evaluate_escalations")
    graph.add_edge("evaluate_escalations", "audit_compliance")
    graph.add_edge("audit_compliance", "report")
    graph.add_edge("report", END)

    return graph


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
