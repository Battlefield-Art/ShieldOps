"""OTel Deployment Orchestrator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelDeployerState
from .nodes import (
    deploy_collectors,
    plan_deployments,
    validate_configs,
    verify_and_report,
)
from .tools import OTelDeployerToolkit


def build_graph(toolkit: OTelDeployerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the OTel Deployment Orchestrator agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _plan(state: Any) -> dict[str, Any]:
        return await plan_deployments(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_configs(_to_dict(state), toolkit)

    async def _deploy(state: Any) -> dict[str, Any]:
        return await deploy_collectors(_to_dict(state), toolkit)

    async def _verify(state: Any) -> dict[str, Any]:
        return await verify_and_report(_to_dict(state), toolkit)

    graph = StateGraph(OTelDeployerState)
    graph.add_node("plan", _plan)
    graph.add_node("validate", _validate)
    graph.add_node("deploy", _deploy)
    graph.add_node("verify", _verify)

    graph.set_entry_point("plan")
    graph.add_edge("plan", "validate")
    graph.add_edge("validate", "deploy")
    graph.add_edge("deploy", "verify")
    graph.add_edge("verify", END)

    return graph


def create_otel_deployer_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Deployment Orchestrator graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelDeployerToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
