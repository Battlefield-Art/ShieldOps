"""Regulatory Change Tracker Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import RegulatoryChangeTrackerState
from .nodes import (
    assess_impact,
    map_controls,
    notify_stakeholders,
    parse_updates,
    report,
    scan_sources,
)
from .tools import RegulatoryChangeTrackerToolkit


def build_graph(toolkit: RegulatoryChangeTrackerToolkit):  # type: ignore[no-untyped-def]
    """Build the regulatory_change_tracker agent graph (linear sequence)."""
    return build_linear_graph(
        RegulatoryChangeTrackerState,
        [
            ("scan_sources", scan_sources),
            ("parse_updates", parse_updates),
            ("assess_impact", assess_impact),
            ("map_controls", map_controls),
            ("notify_stakeholders", notify_stakeholders),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_regulatory_change_tracker_graph(
    reg_feed: Any | None = None,
    control_store: Any | None = None,
    notifier: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Regulatory Change Tracker graph."""
    toolkit = RegulatoryChangeTrackerToolkit(
        reg_feed=reg_feed,
        control_store=control_store,
        notifier=notifier,
    )
    return build_graph(toolkit)
