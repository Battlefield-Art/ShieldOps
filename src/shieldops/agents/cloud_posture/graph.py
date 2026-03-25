"""Cloud Posture Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudPostureState
from .nodes import (
    assess_benchmarks,
    detect_misconfigs,
    generate_report,
    prioritize_risks,
    remediate,
    scan_cloud,
)
from .tools import CloudPostureToolkit


def _should_remediate(state: Any) -> str:
    """Route to remediate if auto-remediable misconfigs exist, else report."""
    if isinstance(state, dict):
        misconfigs = state.get("misconfigurations", [])
    else:
        misconfigs = getattr(state, "misconfigurations", [])

    for m in misconfigs:
        auto_rem = (
            m.get("auto_remediable", False)
            if isinstance(m, dict)
            else getattr(m, "auto_remediable", False)
        )
        if auto_rem:
            return "remediate"
    return "generate_report"


def build_graph(toolkit: CloudPostureToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Posture CSPM agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_cloud(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_benchmarks(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_misconfigs(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_risks(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await remediate(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CloudPostureState)

    # Add nodes
    graph.add_node("scan_cloud", _scan)
    graph.add_node("assess_benchmarks", _assess)
    graph.add_node("detect_misconfigs", _detect)
    graph.add_node("prioritize_risks", _prioritize)
    graph.add_node("remediate", _remediate)
    graph.add_node("generate_report", _report)

    # Linear flow: scan → assess → detect → prioritize
    graph.set_entry_point("scan_cloud")
    graph.add_edge("scan_cloud", "assess_benchmarks")
    graph.add_edge("assess_benchmarks", "detect_misconfigs")
    graph.add_edge("detect_misconfigs", "prioritize_risks")

    # Conditional: if auto-remediable misconfigs → remediate → report; else → report
    graph.add_conditional_edges(
        "prioritize_risks",
        _should_remediate,
        {
            "remediate": "remediate",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("remediate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_posture_graph(
    cloud_clients: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Posture CSPM agent graph with dependencies."""
    toolkit = CloudPostureToolkit(
        cloud_clients=cloud_clients,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
