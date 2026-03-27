"""Data Intelligence Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataIntelligenceState
from .nodes import (
    assess_data_risk,
    classify_with_ai,
    discover_data,
    map_data_lineage,
    recommend_protection,
    report,
)
from .tools import DataIntelligenceToolkit


def build_graph(
    toolkit: DataIntelligenceToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Intelligence agent graph.

    Flow:
        discover_data -> classify_with_ai
        -> map_data_lineage -> assess_data_risk
        -> recommend_protection -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_data(_to_dict(state), toolkit)

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_with_ai(_to_dict(state), toolkit)

    async def _lineage(
        state: Any,
    ) -> dict[str, Any]:
        return await map_data_lineage(_to_dict(state), toolkit)

    async def _risk(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_data_risk(_to_dict(state), toolkit)

    async def _protect(
        state: Any,
    ) -> dict[str, Any]:
        return await recommend_protection(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(DataIntelligenceState)
    graph.add_node("discover_data", _discover)
    graph.add_node("classify_with_ai", _classify)
    graph.add_node("map_data_lineage", _lineage)
    graph.add_node("assess_data_risk", _risk)
    graph.add_node("recommend_protection", _protect)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_data")
    graph.add_edge("discover_data", "classify_with_ai")
    graph.add_edge("classify_with_ai", "map_data_lineage")
    graph.add_edge("map_data_lineage", "assess_data_risk")
    graph.add_edge("assess_data_risk", "recommend_protection")
    graph.add_edge("recommend_protection", "report")
    graph.add_edge("report", END)

    return graph


def create_data_intelligence_graph(
    catalog_client: Any | None = None,
    classifier: Any | None = None,
    lineage_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Intelligence graph."""
    toolkit = DataIntelligenceToolkit(
        catalog_client=catalog_client,
        classifier=classifier,
        lineage_api=lineage_api,
    )
    return build_graph(toolkit)
