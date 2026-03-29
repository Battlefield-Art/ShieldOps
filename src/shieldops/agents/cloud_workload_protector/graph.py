"""Cloud Workload Protector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudWorkloadProtectorState
from .nodes import (
    assess_risk,
    detect_drift,
    inventory_workloads,
    monitor_runtime,
    scan_vulnerabilities,
)
from .tools import CloudWorkloadProtectorToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: CloudWorkloadProtectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Workload Protector agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(state: Any) -> dict[str, Any]:
        return await inventory_workloads(_to_dict(state), toolkit)

    async def _runtime(state: Any) -> dict[str, Any]:
        return await monitor_runtime(_to_dict(state), toolkit)

    async def _drift(state: Any) -> dict[str, Any]:
        return await detect_drift(_to_dict(state), toolkit)

    async def _vulns(state: Any) -> dict[str, Any]:
        return await scan_vulnerabilities(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    graph = StateGraph(CloudWorkloadProtectorState)

    graph.add_node("inventory_workloads", _inventory)
    graph.add_node("monitor_runtime", _runtime)
    graph.add_node("detect_drift", _drift)
    graph.add_node("scan_vulnerabilities", _vulns)
    graph.add_node("assess_risk", _assess)

    graph.set_entry_point("inventory_workloads")
    graph.add_conditional_edges(
        "inventory_workloads",
        _has_error,
        {"end": END, "continue": "monitor_runtime"},
    )
    graph.add_edge("monitor_runtime", "detect_drift")
    graph.add_edge("detect_drift", "scan_vulnerabilities")
    graph.add_edge("scan_vulnerabilities", "assess_risk")
    graph.add_edge("assess_risk", END)

    return graph


def create_cloud_workload_protector_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Workload Protector agent graph."""
    toolkit = CloudWorkloadProtectorToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
