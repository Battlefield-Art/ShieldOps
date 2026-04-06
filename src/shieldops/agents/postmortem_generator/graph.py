"""Postmortem Generator — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: PostmortemGeneratorToolkit):  # type: ignore[no-untyped-def]
    """Build the postmortem_generator agent graph (linear sequence)."""
    return build_linear_graph(
        PostmortemGeneratorState,
        [
            ("collect_timeline", collect_timeline),
            ("analyze_root_cause", analyze_root_cause),
            ("identify_actions", identify_actions),
            ("draft_document", draft_document),
            ("review_quality", review_quality),
            ("report", report),
        ],
        toolkit=toolkit,
    )


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
