"""Cloud Storage Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudStorageScannerState
from .nodes import (
    assess_risk,
    check_encryption,
    detect_sensitive_data,
    discover_buckets,
    scan_access,
)
from .tools import CloudStorageScannerToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: CloudStorageScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Storage Scanner agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_buckets(_to_dict(state), toolkit)

    async def _access(state: Any) -> dict[str, Any]:
        return await scan_access(_to_dict(state), toolkit)

    async def _encryption(state: Any) -> dict[str, Any]:
        return await check_encryption(_to_dict(state), toolkit)

    async def _sensitive(state: Any) -> dict[str, Any]:
        return await detect_sensitive_data(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    graph = StateGraph(CloudStorageScannerState)

    graph.add_node("discover_buckets", _discover)
    graph.add_node("scan_access", _access)
    graph.add_node("check_encryption", _encryption)
    graph.add_node("detect_sensitive_data", _sensitive)
    graph.add_node("assess_risk", _assess)

    graph.set_entry_point("discover_buckets")
    graph.add_conditional_edges(
        "discover_buckets",
        _has_error,
        {"end": END, "continue": "scan_access"},
    )
    graph.add_edge("scan_access", "check_encryption")
    graph.add_edge("check_encryption", "detect_sensitive_data")
    graph.add_edge("detect_sensitive_data", "assess_risk")
    graph.add_edge("assess_risk", END)

    return graph


def create_cloud_storage_scanner_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Storage Scanner agent graph."""
    toolkit = CloudStorageScannerToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
