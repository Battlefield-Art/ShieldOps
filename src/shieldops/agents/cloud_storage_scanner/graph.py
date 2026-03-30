"""Cloud Storage Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudStorageScannerState
from .nodes import (
    assess_encryption,
    detect_sensitive_data,
    discover_buckets,
    generate_report,
    remediate_issues,
    scan_permissions,
)
from .tools import CloudStorageScannerToolkit


def build_graph(
    toolkit: CloudStorageScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Storage Scanner graph.

    Flow:
        discover_buckets -> scan_permissions
        -> detect_sensitive_data -> assess_encryption
        -> remediate_issues -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_buckets(
            _to_dict(state),
            toolkit,
        )

    async def _permissions(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_permissions(
            _to_dict(state),
            toolkit,
        )

    async def _sensitive(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_sensitive_data(
            _to_dict(state),
            toolkit,
        )

    async def _encryption(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_encryption(
            _to_dict(state),
            toolkit,
        )

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await remediate_issues(
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

    graph = StateGraph(CloudStorageScannerState)
    graph.add_node("discover_buckets", _discover)
    graph.add_node(
        "scan_permissions",
        _permissions,
    )
    graph.add_node(
        "detect_sensitive_data",
        _sensitive,
    )
    graph.add_node(
        "assess_encryption",
        _encryption,
    )
    graph.add_node("remediate_issues", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_buckets")
    graph.add_edge(
        "discover_buckets",
        "scan_permissions",
    )
    graph.add_edge(
        "scan_permissions",
        "detect_sensitive_data",
    )
    graph.add_edge(
        "detect_sensitive_data",
        "assess_encryption",
    )
    graph.add_edge(
        "assess_encryption",
        "remediate_issues",
    )
    graph.add_edge(
        "remediate_issues",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_storage_scanner_graph(
    cloud_api: Any | None = None,
    scanner_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Storage Scanner graph."""
    toolkit = CloudStorageScannerToolkit(
        cloud_api=cloud_api,
        scanner_api=scanner_api,
    )
    return build_graph(toolkit)
