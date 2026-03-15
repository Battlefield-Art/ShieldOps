"""OTel Pipeline Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelPipelineState
from .nodes import (
    configure_pipeline,
    discover_pipeline,
    monitor_pipeline,
    validate_pipeline,
)
from .tools import OTelPipelineToolkit


def should_redeploy(state: Any) -> str:
    """Route based on validation result."""
    if hasattr(state, "config_valid"):
        config_valid = state.config_valid
    else:
        config_valid = state.get("config_valid")
    if config_valid:
        return "monitor"
    return "configure"


def build_graph(toolkit: OTelPipelineToolkit) -> StateGraph:
    """Build the OTel Pipeline agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_pipeline(_to_dict(state), toolkit)

    async def _configure(state: Any) -> dict[str, Any]:
        return await configure_pipeline(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_pipeline(_to_dict(state), toolkit)

    async def _monitor(state: Any) -> dict[str, Any]:
        return await monitor_pipeline(_to_dict(state), toolkit)

    graph = StateGraph(OTelPipelineState)
    graph.add_node("discover", _discover)
    graph.add_node("configure", _configure)
    graph.add_node("validate", _validate)
    graph.add_node("monitor", _monitor)

    graph.set_entry_point("discover")
    graph.add_edge("discover", "configure")
    graph.add_edge("configure", "validate")
    graph.add_conditional_edges(
        "validate",
        should_redeploy,
        {
            "monitor": "monitor",
            "configure": "configure",
        },
    )
    graph.add_edge("monitor", END)

    return graph
