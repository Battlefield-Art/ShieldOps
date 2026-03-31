"""Shadow API Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ShadowAPIDetectorState
from .nodes import (
    analyze_endpoints,
    auto_document,
    classify_risk,
    detect_shadow,
    discover_traffic,
    generate_report,
)
from .tools import ShadowAPIDetectorToolkit


def build_graph(
    toolkit: ShadowAPIDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Shadow API Detector graph.

    Flow:
        discover_traffic -> analyze_endpoints
        -> detect_shadow -> classify_risk
        -> auto_document -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_traffic(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_endpoints(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_shadow(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_risk(
            _to_dict(state),
            toolkit,
        )

    async def _document(
        state: Any,
    ) -> dict[str, Any]:
        return await auto_document(
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

    graph = StateGraph(ShadowAPIDetectorState)
    graph.add_node("discover_traffic", _discover)
    graph.add_node("analyze_endpoints", _analyze)
    graph.add_node("detect_shadow", _detect)
    graph.add_node("classify_risk", _classify)
    graph.add_node("auto_document", _document)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_traffic")
    graph.add_edge(
        "discover_traffic",
        "analyze_endpoints",
    )
    graph.add_edge(
        "analyze_endpoints",
        "detect_shadow",
    )
    graph.add_edge(
        "detect_shadow",
        "classify_risk",
    )
    graph.add_edge(
        "classify_risk",
        "auto_document",
    )
    graph.add_edge(
        "auto_document",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_shadow_api_detector_graph(
    traffic_source: Any | None = None,
    api_registry: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Shadow API Detector graph."""
    toolkit = ShadowAPIDetectorToolkit(
        traffic_source=traffic_source,
        api_registry=api_registry,
    )
    return build_graph(toolkit)
