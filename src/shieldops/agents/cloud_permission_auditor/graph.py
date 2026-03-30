"""Cloud Permission Auditor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudPermissionAuditorState
from .nodes import (
    analyze_scope,
    collect_permissions,
    detect_violations,
    generate_fixes,
    generate_report,
    map_cross_account,
)
from .tools import CloudPermissionAuditorToolkit


def build_graph(
    toolkit: CloudPermissionAuditorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Permission Auditor graph.

    Flow:
        collect_permissions -> analyze_scope
        -> detect_violations -> map_cross_account
        -> generate_fixes -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_permissions(
            _to_dict(state),
            toolkit,
        )

    async def _scope(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_scope(
            _to_dict(state),
            toolkit,
        )

    async def _violations(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_violations(
            _to_dict(state),
            toolkit,
        )

    async def _cross_account(
        state: Any,
    ) -> dict[str, Any]:
        return await map_cross_account(
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

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(CloudPermissionAuditorState)
    graph.add_node("collect_permissions", _collect)
    graph.add_node("analyze_scope", _scope)
    graph.add_node("detect_violations", _violations)
    graph.add_node("map_cross_account", _cross_account)
    graph.add_node("generate_fixes", _fixes)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_permissions")
    graph.add_edge(
        "collect_permissions",
        "analyze_scope",
    )
    graph.add_edge(
        "analyze_scope",
        "detect_violations",
    )
    graph.add_edge(
        "detect_violations",
        "map_cross_account",
    )
    graph.add_edge(
        "map_cross_account",
        "generate_fixes",
    )
    graph.add_edge(
        "generate_fixes",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_permission_auditor_graph(
    iam_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Permission Auditor graph."""
    toolkit = CloudPermissionAuditorToolkit(
        iam_api=iam_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
