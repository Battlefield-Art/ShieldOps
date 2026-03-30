"""Security Config Assessor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityConfigAssessorState
from .nodes import (
    benchmark_check,
    detect_drift,
    generate_fixes,
    generate_report,
    inventory_systems,
    scan_configs,
)
from .tools import SecurityConfigAssessorToolkit


def _has_drifts(state: Any) -> str:
    """Route to generate_fixes if drifts exist, else report."""
    drifts = state.get("drifts", []) if isinstance(state, dict) else getattr(state, "drifts", [])

    if drifts:
        return "generate_fixes"
    return "generate_report"


def build_graph(
    toolkit: SecurityConfigAssessorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Config Assessor agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(state: Any) -> dict[str, Any]:
        return await inventory_systems(
            _to_dict(state),
            toolkit,
        )

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_configs(
            _to_dict(state),
            toolkit,
        )

    async def _benchmark(state: Any) -> dict[str, Any]:
        return await benchmark_check(
            _to_dict(state),
            toolkit,
        )

    async def _drift(state: Any) -> dict[str, Any]:
        return await detect_drift(
            _to_dict(state),
            toolkit,
        )

    async def _fixes(state: Any) -> dict[str, Any]:
        return await generate_fixes(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(SecurityConfigAssessorState)

    graph.add_node("inventory_systems", _inventory)
    graph.add_node("scan_configs", _scan)
    graph.add_node("benchmark_check", _benchmark)
    graph.add_node("detect_drift", _drift)
    graph.add_node("generate_fixes", _fixes)
    graph.add_node("generate_report", _report)

    # Linear: inventory -> scan -> benchmark -> drift
    graph.set_entry_point("inventory_systems")
    graph.add_edge("inventory_systems", "scan_configs")
    graph.add_edge("scan_configs", "benchmark_check")
    graph.add_edge("benchmark_check", "detect_drift")

    # Conditional: drifts exist -> fixes -> report; else -> report
    graph.add_conditional_edges(
        "detect_drift",
        _has_drifts,
        {
            "generate_fixes": "generate_fixes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_config_assessor_graph(
    infra_clients: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Security Config Assessor graph."""
    toolkit = SecurityConfigAssessorToolkit(
        infra_clients=infra_clients,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
