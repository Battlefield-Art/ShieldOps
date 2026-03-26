"""AI Compliance Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(toolkit: AIComplianceToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the AI Compliance agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_inventory(state: Any) -> dict[str, Any]:
        return await collect_inventory(_to_dict(state), toolkit)

    async def _classify_risk(state: Any) -> dict[str, Any]:
        return await classify_risk_levels(_to_dict(state), toolkit)

    async def _assess_requirements(state: Any) -> dict[str, Any]:
        return await assess_requirements(_to_dict(state), toolkit)

    async def _evaluate_controls(state: Any) -> dict[str, Any]:
        return await evaluate_controls(_to_dict(state), toolkit)

    async def _generate_evidence(state: Any) -> dict[str, Any]:
        return await generate_evidence(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(AIComplianceState)
    graph.add_node("collect_inventory", _collect_inventory)
    graph.add_node("classify_risk_levels", _classify_risk)
    graph.add_node("assess_requirements", _assess_requirements)
    graph.add_node("evaluate_controls", _evaluate_controls)
    graph.add_node("generate_evidence", _generate_evidence)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("collect_inventory")
    graph.add_edge("collect_inventory", "classify_risk_levels")
    graph.add_edge("classify_risk_levels", "assess_requirements")
    graph.add_edge("assess_requirements", "evaluate_controls")
    graph.add_edge("evaluate_controls", "generate_evidence")
    graph.add_edge("generate_evidence", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


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
