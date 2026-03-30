"""Postmortem Generator — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import PostmortemGeneratorState
from .nodes import (
    analyze_root_cause,
    collect_timeline,
    draft_document,
    identify_actions,
    report,
    review_quality,
)
from .tools import PostmortemGeneratorToolkit

_AGENT = "postmortem_generator"


def _check_error(
    state: PostmortemGeneratorState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: PostmortemGeneratorToolkit,
) -> StateGraph:
    """Build the Postmortem Generator graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _timeline(s: Any) -> dict[str, Any]:
        return await collect_timeline(_d(s))

    async def _rca(s: Any) -> dict[str, Any]:
        return await analyze_root_cause(_d(s))

    async def _actions(s: Any) -> dict[str, Any]:
        return await identify_actions(_d(s))

    async def _draft(s: Any) -> dict[str, Any]:
        return await draft_document(_d(s))

    async def _review(s: Any) -> dict[str, Any]:
        return await review_quality(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(PostmortemGeneratorState)
    g.add_node(
        "collect_timeline",
        traced_node("pmg.timeline", _AGENT)(_timeline),
    )
    g.add_node(
        "analyze_root_cause",
        traced_node("pmg.rca", _AGENT)(_rca),
    )
    g.add_node(
        "identify_actions",
        traced_node("pmg.actions", _AGENT)(_actions),
    )
    g.add_node(
        "draft_document",
        traced_node("pmg.draft", _AGENT)(_draft),
    )
    g.add_node(
        "review_quality",
        traced_node("pmg.review", _AGENT)(_review),
    )
    g.add_node(
        "report",
        traced_node("pmg.report", _AGENT)(_report),
    )

    g.set_entry_point("collect_timeline")
    g.add_edge("collect_timeline", "analyze_root_cause")
    g.add_edge("analyze_root_cause", "identify_actions")
    g.add_edge("identify_actions", "draft_document")
    g.add_edge("draft_document", "review_quality")
    g.add_edge("review_quality", "report")
    g.add_edge("report", END)

    return g


def create_postmortem_generator_graph(
    incident_store: Any | None = None,
    change_store: Any | None = None,
) -> StateGraph:
    """Factory to create the postmortem generator graph."""
    toolkit = PostmortemGeneratorToolkit(
        incident_store=incident_store,
        change_store=change_store,
    )
    return build_graph(toolkit)
