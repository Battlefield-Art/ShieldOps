"""Spam Filter Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SpamFilterManagerState
from .nodes import (
    analyze_false_positives,
    classify_messages,
    collect_rules,
    generate_report,
    manage_quarantine,
    tune_filters,
)
from .tools import SpamFilterManagerToolkit


def build_graph(
    toolkit: SpamFilterManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Spam Filter Manager graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_rules(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_messages(_to_dict(state), toolkit)

    async def _tune(state: Any) -> dict[str, Any]:
        return await tune_filters(_to_dict(state), toolkit)

    async def _fps(state: Any) -> dict[str, Any]:
        return await analyze_false_positives(_to_dict(state), toolkit)

    async def _quarantine(state: Any) -> dict[str, Any]:
        return await manage_quarantine(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SpamFilterManagerState)
    graph.add_node("collect_rules", _collect)
    graph.add_node("classify_messages", _classify)
    graph.add_node("tune_filters", _tune)
    graph.add_node("analyze_false_positives", _fps)
    graph.add_node("manage_quarantine", _quarantine)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_rules")
    graph.add_edge("collect_rules", "classify_messages")
    graph.add_edge("classify_messages", "tune_filters")
    graph.add_edge("tune_filters", "analyze_false_positives")
    graph.add_edge("analyze_false_positives", "manage_quarantine")
    graph.add_edge("manage_quarantine", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_spam_filter_manager_graph(
    filter_client: Any | None = None,
    quarantine_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Spam Filter Manager graph."""
    toolkit = SpamFilterManagerToolkit(
        filter_client=filter_client,
        quarantine_client=quarantine_client,
    )
    return build_graph(toolkit)
