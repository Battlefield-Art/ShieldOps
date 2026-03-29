"""Multi-Cloud Compliance Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import MultiCloudComplianceState
from .nodes import (
    collect_configs,
    evaluate_benchmarks,
    generate_remediation,
    generate_report,
    identify_gaps,
)
from .tools import MultiCloudComplianceToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: MultiCloudComplianceToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Multi-Cloud Compliance agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_configs(_to_dict(state), toolkit)

    async def _evaluate(state: Any) -> dict[str, Any]:
        return await evaluate_benchmarks(_to_dict(state), toolkit)

    async def _gaps(state: Any) -> dict[str, Any]:
        return await identify_gaps(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await generate_remediation(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(MultiCloudComplianceState)

    graph.add_node("collect_configs", _collect)
    graph.add_node("evaluate_benchmarks", _evaluate)
    graph.add_node("identify_gaps", _gaps)
    graph.add_node("generate_remediation", _remediate)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_configs")
    graph.add_conditional_edges(
        "collect_configs",
        _has_error,
        {"end": END, "continue": "evaluate_benchmarks"},
    )
    graph.add_edge("evaluate_benchmarks", "identify_gaps")
    graph.add_edge("identify_gaps", "generate_remediation")
    graph.add_edge("generate_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_multi_cloud_compliance_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Multi-Cloud Compliance agent graph."""
    toolkit = MultiCloudComplianceToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
