"""Adaptive Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AdaptiveSecurityState
from .nodes import (
    apply_accepted,
    compute_baseline,
    detect_and_propose,
    evaluate_proposals,
)
from .tools import AdaptiveSecurityToolkit


def _should_apply(state: Any) -> str:
    """Route based on whether any proposals were accepted."""
    if hasattr(state, "accepted_count"):
        accepted = state.accepted_count
    else:
        accepted = state.get("accepted_count", 0)
    if accepted > 0:
        return "apply"
    return "end"


def build_graph(toolkit: AdaptiveSecurityToolkit) -> StateGraph:
    """Build the Adaptive Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _baseline(state: Any) -> dict[str, Any]:
        return await compute_baseline(_to_dict(state), toolkit)

    async def _detect_propose(state: Any) -> dict[str, Any]:
        return await detect_and_propose(_to_dict(state), toolkit)

    async def _evaluate(state: Any) -> dict[str, Any]:
        return await evaluate_proposals(_to_dict(state), toolkit)

    async def _apply(state: Any) -> dict[str, Any]:
        return await apply_accepted(_to_dict(state), toolkit)

    graph = StateGraph(AdaptiveSecurityState)
    graph.add_node("baseline", _baseline)
    graph.add_node("detect_and_propose", _detect_propose)
    graph.add_node("evaluate", _evaluate)
    graph.add_node("apply", _apply)

    graph.set_entry_point("baseline")
    graph.add_edge("baseline", "detect_and_propose")
    graph.add_edge("detect_and_propose", "evaluate")
    graph.add_conditional_edges(
        "evaluate",
        _should_apply,
        {"apply": "apply", "end": END},
    )
    graph.add_edge("apply", END)

    return graph


def create_adaptive_security_graph(
    siem_client: Any | None = None,
    metrics_store: Any | None = None,
    policy_engine: Any | None = None,
) -> StateGraph:
    """Create the Adaptive Security agent graph with dependencies."""
    toolkit = AdaptiveSecurityToolkit(
        siem_client=siem_client,
        metrics_store=metrics_store,
        policy_engine=policy_engine,
    )
    return build_graph(toolkit)
