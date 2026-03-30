"""Threat Feed Aggregator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ThreatFeedAggregatorState
from .nodes import (
    collect_feeds,
    correlate_threats,
    distribute_intel,
    enrich_context,
    generate_report,
    normalize_iocs,
)
from .tools import ThreatFeedAggregatorToolkit


def build_graph(
    toolkit: ThreatFeedAggregatorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Feed Aggregator graph.

    Flow:
        collect_feeds -> normalize_iocs
        -> correlate_threats -> enrich_context
        -> distribute_intel -> report
    """

    def _to_dict(
        state: Any,
    ) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_feeds(
            _to_dict(state),
            toolkit,
        )

    async def _normalize(
        state: Any,
    ) -> dict[str, Any]:
        return await normalize_iocs(
            _to_dict(state),
            toolkit,
        )

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_threats(
            _to_dict(state),
            toolkit,
        )

    async def _enrich(
        state: Any,
    ) -> dict[str, Any]:
        return await enrich_context(
            _to_dict(state),
            toolkit,
        )

    async def _distribute(
        state: Any,
    ) -> dict[str, Any]:
        return await distribute_intel(
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

    graph = StateGraph(ThreatFeedAggregatorState)
    graph.add_node("collect_feeds", _collect)
    graph.add_node("normalize_iocs", _normalize)
    graph.add_node(
        "correlate_threats",
        _correlate,
    )
    graph.add_node("enrich_context", _enrich)
    graph.add_node(
        "distribute_intel",
        _distribute,
    )
    graph.add_node("report", _report)

    graph.set_entry_point("collect_feeds")
    graph.add_edge(
        "collect_feeds",
        "normalize_iocs",
    )
    graph.add_edge(
        "normalize_iocs",
        "correlate_threats",
    )
    graph.add_edge(
        "correlate_threats",
        "enrich_context",
    )
    graph.add_edge(
        "enrich_context",
        "distribute_intel",
    )
    graph.add_edge(
        "distribute_intel",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_threat_feed_aggregator_graph(
    misp_client: Any | None = None,
    taxii_client: Any | None = None,
    otx_client: Any | None = None,
    vt_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Threat Feed Aggregator graph."""
    toolkit = ThreatFeedAggregatorToolkit(
        misp_client=misp_client,
        taxii_client=taxii_client,
        otx_client=otx_client,
        vt_client=vt_client,
    )
    return build_graph(toolkit)
