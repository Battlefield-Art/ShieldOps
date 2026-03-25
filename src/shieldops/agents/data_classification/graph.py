"""Data Classification Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataClassificationState
from .nodes import (
    classify_level,
    detect_sensitive,
    enforce_labels,
    map_regulations,
    report,
    scan_sources,
)
from .tools import DataClassificationToolkit


def _has_findings(state: Any) -> str:
    """Route based on whether sensitive findings exist."""
    if hasattr(state, "sensitive_findings"):
        findings = state.sensitive_findings
    else:
        findings = state.get("sensitive_findings", [])
    if findings:
        return "enforce"
    return "report"


def build_graph(
    toolkit: DataClassificationToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Classification agent graph.

    Flow: scan_sources → detect_sensitive → classify_level → map_regulations
          → (findings?) → enforce_labels → report | report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_sources(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_sensitive(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_level(_to_dict(state), toolkit)

    async def _regulations(state: Any) -> dict[str, Any]:
        return await map_regulations(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_labels(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(DataClassificationState)
    graph.add_node("scan_sources", _scan)
    graph.add_node("detect_sensitive", _detect)
    graph.add_node("classify_level", _classify)
    graph.add_node("map_regulations", _regulations)
    graph.add_node("enforce_labels", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_sources")
    graph.add_edge("scan_sources", "detect_sensitive")
    graph.add_edge("detect_sensitive", "classify_level")
    graph.add_edge("classify_level", "map_regulations")
    graph.add_conditional_edges(
        "map_regulations",
        _has_findings,
        {"enforce": "enforce_labels", "report": "report"},
    )
    graph.add_edge("enforce_labels", "report")
    graph.add_edge("report", END)

    return graph


def create_data_classification_graph(
    db_connector: Any | None = None,
    storage_connector: Any | None = None,
    label_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Classification graph with dependencies."""
    toolkit = DataClassificationToolkit(
        db_connector=db_connector,
        storage_connector=storage_connector,
        label_api=label_api,
    )
    return build_graph(toolkit)
