"""Spam Filter Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: SpamFilterManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the spam_filter_manager agent graph (linear sequence)."""
    return build_linear_graph(
        SpamFilterManagerState,
        [
            ("collect_rules", collect_rules),
            ("classify_messages", classify_messages),
            ("tune_filters", tune_filters),
            ("analyze_false_positives", analyze_false_positives),
            ("manage_quarantine", manage_quarantine),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


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
