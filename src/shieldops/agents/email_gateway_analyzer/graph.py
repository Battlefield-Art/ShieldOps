"""Email Gateway Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import GatewayAnalyzerState
from .nodes import (
    analyze_headers,
    check_reputation,
    collect_records,
    detect_spoofing,
    generate_report,
    validate_auth,
)
from .tools import EmailGatewayAnalyzerToolkit


def _has_spoofing(state: Any) -> str:
    """Route: deeper analysis if spoofing detected."""
    if hasattr(state, "spoofing_detected"):
        count = state.spoofing_detected
    else:
        count = state.get("spoofing_detected", 0)
    return "report" if count == 0 else "report_with_spoofing"


def build_graph(
    toolkit: EmailGatewayAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Email Gateway Analyzer graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_records(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_auth(_to_dict(state), toolkit)

    async def _headers(state: Any) -> dict[str, Any]:
        return await analyze_headers(_to_dict(state), toolkit)

    async def _reputation(state: Any) -> dict[str, Any]:
        return await check_reputation(_to_dict(state), toolkit)

    async def _spoofing(state: Any) -> dict[str, Any]:
        return await detect_spoofing(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(GatewayAnalyzerState)
    graph.add_node("collect_records", _collect)
    graph.add_node("validate_auth", _validate)
    graph.add_node("analyze_headers", _headers)
    graph.add_node("check_reputation", _reputation)
    graph.add_node("detect_spoofing", _spoofing)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_records")
    graph.add_edge("collect_records", "validate_auth")
    graph.add_edge("validate_auth", "analyze_headers")
    graph.add_edge("analyze_headers", "check_reputation")
    graph.add_edge("check_reputation", "detect_spoofing")
    graph.add_edge("detect_spoofing", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_email_gateway_analyzer_graph(
    dns_client: Any | None = None,
    reputation_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Email Gateway Analyzer graph."""
    toolkit = EmailGatewayAnalyzerToolkit(
        dns_client=dns_client,
        reputation_client=reputation_client,
    )
    return build_graph(toolkit)
