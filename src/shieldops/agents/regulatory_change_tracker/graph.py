"""Regulatory Change Tracker Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

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

_AGENT = "regulatory_change_tracker"


def _check_error(
    state: RegulatoryChangeTrackerState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: RegulatoryChangeTrackerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Regulatory Change Tracker graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_sources(
            _to_dict(state),
            toolkit,
        )

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_updates(
            _to_dict(state),
            toolkit,
        )

    async def _impact(state: Any) -> dict[str, Any]:
        return await assess_impact(
            _to_dict(state),
            toolkit,
        )

    async def _map(state: Any) -> dict[str, Any]:
        return await map_controls(
            _to_dict(state),
            toolkit,
        )

    async def _notify(state: Any) -> dict[str, Any]:
        return await notify_stakeholders(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(RegulatoryChangeTrackerState)
    graph.add_node(
        "scan_sources",
        traced_node("rct.scan_sources", _AGENT)(_scan),
    )
    graph.add_node(
        "parse_updates",
        traced_node("rct.parse_updates", _AGENT)(_parse),
    )
    graph.add_node(
        "assess_impact",
        traced_node("rct.assess_impact", _AGENT)(_impact),
    )
    graph.add_node(
        "map_controls",
        traced_node("rct.map_controls", _AGENT)(_map),
    )
    graph.add_node(
        "notify_stakeholders",
        traced_node("rct.notify_stakeholders", _AGENT)(_notify),
    )
    graph.add_node(
        "report",
        traced_node("rct.report", _AGENT)(_report),
    )

    graph.set_entry_point("scan_sources")
    graph.add_edge("scan_sources", "parse_updates")
    graph.add_edge("parse_updates", "assess_impact")
    graph.add_edge("assess_impact", "map_controls")
    graph.add_edge("map_controls", "notify_stakeholders")
    graph.add_edge("notify_stakeholders", "report")
    graph.add_edge("report", END)

    return graph


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
