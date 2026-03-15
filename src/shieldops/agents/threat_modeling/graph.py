"""Threat Modeling Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ThreatModelingState
from .nodes import (
    analyze_threats,
    assess_risk,
    discover_architecture,
    recommend_mitigations,
)
from .tools import ThreatModelingToolkit


def build_graph(toolkit: ThreatModelingToolkit) -> StateGraph:
    """Build the Threat Modeling agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_architecture(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_threats(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _mitigate(state: Any) -> dict[str, Any]:
        return await recommend_mitigations(_to_dict(state), toolkit)

    graph = StateGraph(ThreatModelingState)
    graph.add_node("discover_architecture", _discover)
    graph.add_node("analyze_threats", _analyze)
    graph.add_node("assess_risk", _assess)
    graph.add_node("recommend_mitigations", _mitigate)

    graph.set_entry_point("discover_architecture")
    graph.add_edge("discover_architecture", "analyze_threats")
    graph.add_edge("analyze_threats", "assess_risk")
    graph.add_edge("assess_risk", "recommend_mitigations")
    graph.add_edge("recommend_mitigations", END)

    return graph


def create_threat_modeling_graph(
    rba_client: Any | None = None,
    architecture_registry: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:
    """Create the Threat Modeling agent graph with dependencies."""
    toolkit = ThreatModelingToolkit(
        rba_client=rba_client,
        architecture_registry=architecture_registry,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
