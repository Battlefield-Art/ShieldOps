"""Security Change Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityChangeManagerState
from .nodes import (
    approve_or_reject,
    assess_risk,
    check_dependencies,
    generate_report,
    monitor_rollout,
    receive_change,
)
from .tools import SecurityChangeManagerToolkit


def build_graph(
    toolkit: SecurityChangeManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Change Manager graph.

    Flow:
        receive_change -> assess_risk
        -> check_dependencies -> approve_or_reject
        -> monitor_rollout -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _receive(
        state: Any,
    ) -> dict[str, Any]:
        return await receive_change(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(
            _to_dict(state),
            toolkit,
        )

    async def _check_deps(
        state: Any,
    ) -> dict[str, Any]:
        return await check_dependencies(
            _to_dict(state),
            toolkit,
        )

    async def _approve(
        state: Any,
    ) -> dict[str, Any]:
        return await approve_or_reject(
            _to_dict(state),
            toolkit,
        )

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_rollout(
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

    graph = StateGraph(SecurityChangeManagerState)
    graph.add_node("receive_change", _receive)
    graph.add_node("assess_risk", _assess)
    graph.add_node("check_dependencies", _check_deps)
    graph.add_node("approve_or_reject", _approve)
    graph.add_node("monitor_rollout", _monitor)
    graph.add_node("report", _report)

    graph.set_entry_point("receive_change")
    graph.add_edge(
        "receive_change",
        "assess_risk",
    )
    graph.add_edge(
        "assess_risk",
        "check_dependencies",
    )
    graph.add_edge(
        "check_dependencies",
        "approve_or_reject",
    )
    graph.add_edge(
        "approve_or_reject",
        "monitor_rollout",
    )
    graph.add_edge(
        "monitor_rollout",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_change_manager_graph(
    change_source: Any | None = None,
    approval_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Change Manager graph."""
    toolkit = SecurityChangeManagerToolkit(
        change_source=change_source,
        approval_api=approval_api,
    )
    return build_graph(toolkit)
