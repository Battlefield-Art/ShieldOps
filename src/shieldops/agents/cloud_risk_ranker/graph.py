"""Cloud Risk Ranker Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudRiskRankerState
from .nodes import (
    collect_cloud_findings,
    correlate_attacker_tactics,
    generate_attack_paths,
    generate_report,
    prioritize_remediation,
    rank_by_exploitability,
)
from .tools import CloudRiskRankerToolkit


def _has_critical_paths(state: Any) -> str:
    """Route based on whether critical attack paths exist."""
    if isinstance(state, dict):
        paths = state.get("attack_paths", [])
    else:
        paths = getattr(state, "attack_paths", [])

    for p in paths:
        score = (
            p.get("overall_risk_score", 0)
            if isinstance(p, dict)
            else getattr(p, "overall_risk_score", 0)
        )
        if score >= 80.0:
            return "prioritize_remediation"
    return "prioritize_remediation"


def build_graph(
    toolkit: CloudRiskRankerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Risk Ranker agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_cloud_findings(_to_dict(state), toolkit)

    async def _correlate(state: Any) -> dict[str, Any]:
        return await correlate_attacker_tactics(_to_dict(state), toolkit)

    async def _rank(state: Any) -> dict[str, Any]:
        return await rank_by_exploitability(_to_dict(state), toolkit)

    async def _paths(state: Any) -> dict[str, Any]:
        return await generate_attack_paths(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_remediation(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CloudRiskRankerState)

    # Add nodes
    graph.add_node("collect_cloud_findings", _collect)
    graph.add_node("correlate_attacker_tactics", _correlate)
    graph.add_node("rank_by_exploitability", _rank)
    graph.add_node("generate_attack_paths", _paths)
    graph.add_node("prioritize_remediation", _prioritize)
    graph.add_node("generate_report", _report)

    # Linear flow: collect -> correlate -> rank -> paths
    graph.set_entry_point("collect_cloud_findings")
    graph.add_edge(
        "collect_cloud_findings",
        "correlate_attacker_tactics",
    )
    graph.add_edge(
        "correlate_attacker_tactics",
        "rank_by_exploitability",
    )
    graph.add_edge(
        "rank_by_exploitability",
        "generate_attack_paths",
    )

    # Conditional: route after attack paths
    graph.add_conditional_edges(
        "generate_attack_paths",
        _has_critical_paths,
        {
            "prioritize_remediation": "prioritize_remediation",
        },
    )
    graph.add_edge("prioritize_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_risk_ranker_graph(
    cloud_clients: Any | None = None,
    threat_intel_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Risk Ranker agent graph with deps."""
    toolkit = CloudRiskRankerToolkit(
        cloud_clients=cloud_clients,
        threat_intel_client=threat_intel_client,
    )
    return build_graph(toolkit)
