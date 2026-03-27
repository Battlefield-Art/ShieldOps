"""Unified Cloud Security Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import UnifiedCloudSecurityState
from .nodes import (
    assess_posture,
    collect_cloud_state,
    detect_threats,
    orchestrate_response,
    prioritize_risks,
    report,
)
from .tools import UnifiedCloudSecurityToolkit


def build_graph(
    toolkit: UnifiedCloudSecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Unified Cloud Security graph.

    Flow:
        collect_cloud_state -> assess_posture
        -> detect_threats -> prioritize_risks
        -> orchestrate_response -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_cloud_state(_to_dict(state), toolkit)

    async def _posture(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_posture(_to_dict(state), toolkit)

    async def _threats(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_threats(_to_dict(state), toolkit)

    async def _prioritize(
        state: Any,
    ) -> dict[str, Any]:
        return await prioritize_risks(_to_dict(state), toolkit)

    async def _respond(
        state: Any,
    ) -> dict[str, Any]:
        return await orchestrate_response(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(UnifiedCloudSecurityState)
    graph.add_node("collect_cloud_state", _collect)
    graph.add_node("assess_posture", _posture)
    graph.add_node("detect_threats", _threats)
    graph.add_node("prioritize_risks", _prioritize)
    graph.add_node("orchestrate_response", _respond)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_cloud_state")
    graph.add_edge("collect_cloud_state", "assess_posture")
    graph.add_edge("assess_posture", "detect_threats")
    graph.add_edge("detect_threats", "prioritize_risks")
    graph.add_edge(
        "prioritize_risks",
        "orchestrate_response",
    )
    graph.add_edge("orchestrate_response", "report")
    graph.add_edge("report", END)

    return graph


def create_unified_cloud_security_graph(
    aws_client: Any | None = None,
    gcp_client: Any | None = None,
    azure_client: Any | None = None,
    k8s_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Unified Cloud Security graph."""
    toolkit = UnifiedCloudSecurityToolkit(
        aws_client=aws_client,
        gcp_client=gcp_client,
        azure_client=azure_client,
        k8s_client=k8s_client,
    )
    return build_graph(toolkit)
