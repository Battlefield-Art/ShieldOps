"""Data Sovereignty Enforcer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataSovereigntyEnforcerState
from .nodes import (
    check_residency,
    discover_data_flows,
    enforce_policies,
    map_jurisdictions,
    report,
    validate_transfers,
)
from .tools import DataSovereigntyEnforcerToolkit


def _has_violations(state: Any) -> str:
    """Route based on whether residency violations or invalid transfers exist."""
    if hasattr(state, "residency_violations"):
        violations = state.residency_violations
    else:
        violations = state.get("residency_violations", [])

    if hasattr(state, "transfer_validations"):
        validations = state.transfer_validations
    else:
        validations = state.get("transfer_validations", [])

    has_violations = bool(violations)
    has_invalid = any(not v.get("valid", True) for v in (validations or []))

    if has_violations or has_invalid:
        return "enforce"
    return "report"


def build_graph(
    toolkit: DataSovereigntyEnforcerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Sovereignty Enforcer agent graph.

    Flow: discover_data_flows → map_jurisdictions → check_residency
          → validate_transfers → (violations?) → enforce_policies → report | report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_data_flows(_to_dict(state), toolkit)

    async def _map_j(state: Any) -> dict[str, Any]:
        return await map_jurisdictions(_to_dict(state), toolkit)

    async def _residency(state: Any) -> dict[str, Any]:
        return await check_residency(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_transfers(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(DataSovereigntyEnforcerState)
    graph.add_node("discover_data_flows", _discover)
    graph.add_node("map_jurisdictions", _map_j)
    graph.add_node("check_residency", _residency)
    graph.add_node("validate_transfers", _validate)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_data_flows")
    graph.add_edge("discover_data_flows", "map_jurisdictions")
    graph.add_edge("map_jurisdictions", "check_residency")
    graph.add_edge("check_residency", "validate_transfers")
    graph.add_conditional_edges(
        "validate_transfers",
        _has_violations,
        {"enforce": "enforce_policies", "report": "report"},
    )
    graph.add_edge("enforce_policies", "report")
    graph.add_edge("report", END)

    return graph


def create_data_sovereignty_enforcer_graph(
    flow_connector: Any | None = None,
    policy_engine: Any | None = None,
    geo_fence_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Sovereignty Enforcer graph with dependencies."""
    toolkit = DataSovereigntyEnforcerToolkit(
        flow_connector=flow_connector,
        policy_engine=policy_engine,
        geo_fence_api=geo_fence_api,
    )
    return build_graph(toolkit)
