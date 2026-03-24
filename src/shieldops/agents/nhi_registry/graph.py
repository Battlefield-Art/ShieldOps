"""NHI Registry Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import NHIRegistryState
from .nodes import (
    assess_risk,
    classify_identities,
    detect_shadow_ai,
    generate_recommendations,
    report,
    scan_cicd,
    scan_cloud_iam,
    scan_kubernetes,
)
from .tools import NHIRegistryToolkit


def build_graph(toolkit: NHIRegistryToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the NHI Registry agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_cloud_iam(state: Any) -> dict[str, Any]:
        return await scan_cloud_iam(_to_dict(state), toolkit)

    async def _scan_kubernetes(state: Any) -> dict[str, Any]:
        return await scan_kubernetes(_to_dict(state), toolkit)

    async def _scan_cicd(state: Any) -> dict[str, Any]:
        return await scan_cicd(_to_dict(state), toolkit)

    async def _detect_shadow_ai(state: Any) -> dict[str, Any]:
        return await detect_shadow_ai(_to_dict(state), toolkit)

    async def _classify_identities(state: Any) -> dict[str, Any]:
        return await classify_identities(_to_dict(state), toolkit)

    async def _assess_risk(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _generate_recommendations(state: Any) -> dict[str, Any]:
        return await generate_recommendations(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(NHIRegistryState)
    graph.add_node("scan_cloud_iam", _scan_cloud_iam)
    graph.add_node("scan_kubernetes", _scan_kubernetes)
    graph.add_node("scan_cicd", _scan_cicd)
    graph.add_node("detect_shadow_ai", _detect_shadow_ai)
    graph.add_node("classify_identities", _classify_identities)
    graph.add_node("assess_risk", _assess_risk)
    graph.add_node("generate_recommendations", _generate_recommendations)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_cloud_iam")
    graph.add_edge("scan_cloud_iam", "scan_kubernetes")
    graph.add_edge("scan_kubernetes", "scan_cicd")
    graph.add_edge("scan_cicd", "detect_shadow_ai")
    graph.add_edge("detect_shadow_ai", "classify_identities")
    graph.add_edge("classify_identities", "assess_risk")
    graph.add_edge("assess_risk", "generate_recommendations")
    graph.add_edge("generate_recommendations", "report")
    graph.add_edge("report", END)

    return graph


def create_nhi_registry_graph(
    aws_client: Any | None = None,
    gcp_client: Any | None = None,
    azure_client: Any | None = None,
    k8s_client: Any | None = None,
    github_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the NHI Registry agent graph with dependencies."""
    toolkit = NHIRegistryToolkit(
        aws_client=aws_client,
        gcp_client=gcp_client,
        azure_client=azure_client,
        k8s_client=k8s_client,
        github_client=github_client,
    )
    return build_graph(toolkit)
