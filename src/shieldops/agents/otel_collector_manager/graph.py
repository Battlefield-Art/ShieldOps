"""OTel Collector Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelCollectorManagerState
from .nodes import (
    assess_requirements,
    deploy_and_verify,
    generate_config,
    monitor_health,
)
from .tools import OTelCollectorManagerToolkit


def build_graph(toolkit: OTelCollectorManagerToolkit) -> StateGraph:
    """Build the OTel Collector Manager agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_requirements(_to_dict(state), toolkit)

    async def _generate(state: Any) -> dict[str, Any]:
        return await generate_config(_to_dict(state), toolkit)

    async def _deploy(state: Any) -> dict[str, Any]:
        return await deploy_and_verify(_to_dict(state), toolkit)

    async def _monitor(state: Any) -> dict[str, Any]:
        return await monitor_health(_to_dict(state), toolkit)

    graph = StateGraph(OTelCollectorManagerState)
    graph.add_node("assess", _assess)
    graph.add_node("generate", _generate)
    graph.add_node("deploy", _deploy)
    graph.add_node("monitor", _monitor)

    graph.set_entry_point("assess")
    graph.add_edge("assess", "generate")
    graph.add_edge("generate", "deploy")
    graph.add_edge("deploy", "monitor")
    graph.add_edge("monitor", END)

    return graph


def create_otel_collector_manager_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:
    """Create and return the OTel Collector Manager graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelCollectorManagerToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
