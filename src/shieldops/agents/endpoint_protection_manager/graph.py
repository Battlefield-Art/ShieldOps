"""Endpoint Protection Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EndpointProtectionManagerState
from .nodes import (
    assess_patches,
    check_agents,
    generate_report,
    inventory_endpoints,
    remediate_gaps,
    scan_malware,
)
from .tools import EndpointProtectionManagerToolkit


def build_graph(
    toolkit: EndpointProtectionManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Endpoint Protection Manager graph.

    Flow:
        inventory_endpoints -> check_agents
        -> assess_patches -> scan_malware
        -> remediate_gaps -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_endpoints(
            _to_dict(state),
            toolkit,
        )

    async def _check(
        state: Any,
    ) -> dict[str, Any]:
        return await check_agents(
            _to_dict(state),
            toolkit,
        )

    async def _patches(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_patches(
            _to_dict(state),
            toolkit,
        )

    async def _malware(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_malware(
            _to_dict(state),
            toolkit,
        )

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await remediate_gaps(
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

    graph = StateGraph(EndpointProtectionManagerState)
    graph.add_node("inventory_endpoints", _inventory)
    graph.add_node("check_agents", _check)
    graph.add_node("assess_patches", _patches)
    graph.add_node("scan_malware", _malware)
    graph.add_node("remediate_gaps", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("inventory_endpoints")
    graph.add_edge(
        "inventory_endpoints",
        "check_agents",
    )
    graph.add_edge(
        "check_agents",
        "assess_patches",
    )
    graph.add_edge(
        "assess_patches",
        "scan_malware",
    )
    graph.add_edge(
        "scan_malware",
        "remediate_gaps",
    )
    graph.add_edge(
        "remediate_gaps",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_endpoint_protection_manager_graph(
    edr_api: Any | None = None,
    cmdb_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Protection Manager graph."""
    toolkit = EndpointProtectionManagerToolkit(
        edr_api=edr_api,
        cmdb_api=cmdb_api,
    )
    return build_graph(toolkit)
