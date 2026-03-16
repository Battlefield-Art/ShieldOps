"""OTel Tail Sampling Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelTailSamplingState
from .nodes import (
    analyze_traces,
    apply_policies,
    design_policies,
    simulate_impact,
)
from .tools import OTelTailSamplingToolkit


def _should_apply(state: Any) -> str:
    """Conditional edge: apply policies only if savings exceed 10%."""
    if hasattr(state, "cost_savings_pct"):
        savings = state.cost_savings_pct
    elif isinstance(state, dict):
        savings = state.get("cost_savings_pct", 0.0)
    else:
        savings = 0.0

    if savings > 10.0:
        return "apply"
    return "end"


def build_graph(toolkit: OTelTailSamplingToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the OTel Tail Sampling agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_traces(_to_dict(state), toolkit)

    async def _design(state: Any) -> dict[str, Any]:
        return await design_policies(_to_dict(state), toolkit)

    async def _simulate(state: Any) -> dict[str, Any]:
        return await simulate_impact(_to_dict(state), toolkit)

    async def _apply(state: Any) -> dict[str, Any]:
        return await apply_policies(_to_dict(state), toolkit)

    graph = StateGraph(OTelTailSamplingState)
    graph.add_node("analyze", _analyze)
    graph.add_node("design", _design)
    graph.add_node("simulate", _simulate)
    graph.add_node("apply", _apply)

    graph.set_entry_point("analyze")
    graph.add_edge("analyze", "design")
    graph.add_edge("design", "simulate")
    graph.add_conditional_edges(
        "simulate",
        _should_apply,
        {"apply": "apply", "end": END},
    )
    graph.add_edge("apply", END)

    return graph


def create_otel_tail_sampling_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Tail Sampling graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelTailSamplingToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
