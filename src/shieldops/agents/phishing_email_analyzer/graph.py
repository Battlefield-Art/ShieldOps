"""Phishing Email Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PhishingEmailAnalyzerState
from .nodes import (
    analyze_content,
    analyze_sender,
    analyze_urls,
    generate_report,
    ingest_email,
    score_risk,
)
from .tools import PhishingEmailAnalyzerToolkit


def build_graph(
    toolkit: PhishingEmailAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Phishing Email Analyzer graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_email(_to_dict(state), toolkit)

    async def _sender(state: Any) -> dict[str, Any]:
        return await analyze_sender(_to_dict(state), toolkit)

    async def _urls(state: Any) -> dict[str, Any]:
        return await analyze_urls(_to_dict(state), toolkit)

    async def _content(state: Any) -> dict[str, Any]:
        return await analyze_content(_to_dict(state), toolkit)

    async def _score(state: Any) -> dict[str, Any]:
        return await score_risk(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PhishingEmailAnalyzerState)
    graph.add_node("ingest_email", _ingest)
    graph.add_node("analyze_sender", _sender)
    graph.add_node("analyze_urls", _urls)
    graph.add_node("analyze_content", _content)
    graph.add_node("score_risk", _score)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("ingest_email")
    graph.add_edge("ingest_email", "analyze_sender")
    graph.add_edge("analyze_sender", "analyze_urls")
    graph.add_edge("analyze_urls", "analyze_content")
    graph.add_edge("analyze_content", "score_risk")
    graph.add_edge("score_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_phishing_email_analyzer_graph(
    url_scanner: Any | None = None,
    reputation_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Phishing Email Analyzer graph."""
    toolkit = PhishingEmailAnalyzerToolkit(
        url_scanner=url_scanner,
        reputation_client=reputation_client,
    )
    return build_graph(toolkit)
