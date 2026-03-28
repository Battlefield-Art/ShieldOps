"""API Rate Limiter — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import APIRateLimiterState
from .nodes import (
    classify_threats,
    detect_abuse,
    enforce_limits,
    generate_report,
    ingest_requests,
    profile_clients,
)
from .tools import APIRateLimiterToolkit


def _has_abuse(state: Any) -> str:
    """Route based on whether abuse patterns were detected."""
    if hasattr(state, "abuse_detections"):
        detections = state.abuse_detections
    else:
        detections = state.get("abuse_detections", [])
    if detections:
        return "enforce"
    return "report"


def build_graph(
    toolkit: APIRateLimiterToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the API Rate Limiter graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_requests(_to_dict(state), toolkit)

    async def _profile(state: Any) -> dict[str, Any]:
        return await profile_clients(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_abuse(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_threats(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_limits(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(APIRateLimiterState)
    graph.add_node("ingest_requests", _ingest)
    graph.add_node("profile_clients", _profile)
    graph.add_node("detect_abuse", _detect)
    graph.add_node("classify_threats", _classify)
    graph.add_node("enforce_limits", _enforce)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("ingest_requests")
    graph.add_edge("ingest_requests", "profile_clients")
    graph.add_edge("profile_clients", "detect_abuse")
    graph.add_conditional_edges(
        "detect_abuse",
        _has_abuse,
        {"enforce": "classify_threats", "report": "generate_report"},
    )
    graph.add_edge("classify_threats", "enforce_limits")
    graph.add_edge("enforce_limits", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_api_rate_limiter_graph(
    redis_client: Any | None = None,
    alert_sink: Any | None = None,
    geo_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the API Rate Limiter graph with dependencies."""
    toolkit = APIRateLimiterToolkit(
        redis_client=redis_client,
        alert_sink=alert_sink,
        geo_service=geo_service,
    )
    return build_graph(toolkit)
