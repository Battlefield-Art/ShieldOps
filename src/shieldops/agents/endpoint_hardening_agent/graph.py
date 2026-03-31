"""Endpoint Hardening Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EndpointHardeningAgentState
from .nodes import (
    apply_hardening,
    check_baseline,
    detect_deviations,
    generate_fixes,
    generate_report,
    scan_endpoints,
)
from .tools import EndpointHardeningAgentToolkit


def build_graph(
    toolkit: EndpointHardeningAgentToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Endpoint Hardening Agent graph.

    Flow:
        scan_endpoints -> check_baseline
        -> detect_deviations -> generate_fixes
        -> apply_hardening -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_endpoints(
            _to_dict(state),
            toolkit,
        )

    async def _baseline(
        state: Any,
    ) -> dict[str, Any]:
        return await check_baseline(
            _to_dict(state),
            toolkit,
        )

    async def _deviations(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_deviations(
            _to_dict(state),
            toolkit,
        )

    async def _fixes(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_fixes(
            _to_dict(state),
            toolkit,
        )

    async def _apply(
        state: Any,
    ) -> dict[str, Any]:
        return await apply_hardening(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(EndpointHardeningAgentState)
    graph.add_node("scan_endpoints", _scan)
    graph.add_node("check_baseline", _baseline)
    graph.add_node("detect_deviations", _deviations)
    graph.add_node("generate_fixes", _fixes)
    graph.add_node("apply_hardening", _apply)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_endpoints")
    graph.add_edge(
        "scan_endpoints",
        "check_baseline",
    )
    graph.add_edge(
        "check_baseline",
        "detect_deviations",
    )
    graph.add_edge(
        "detect_deviations",
        "generate_fixes",
    )
    graph.add_edge(
        "generate_fixes",
        "apply_hardening",
    )
    graph.add_edge(
        "apply_hardening",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_endpoint_hardening_agent_graph(
    endpoint_api: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Hardening Agent graph."""
    toolkit = EndpointHardeningAgentToolkit(
        endpoint_api=endpoint_api,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
