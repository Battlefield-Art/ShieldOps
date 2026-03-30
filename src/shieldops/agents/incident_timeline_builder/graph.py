"""Incident Timeline Builder Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import IncidentTimelineBuilderState
from .nodes import (
    build_timeline,
    collect_events,
    correlate_sources,
    generate_narrative,
    generate_report,
    identify_root_cause,
)
from .tools import IncidentTimelineBuilderToolkit


def build_graph(
    toolkit: IncidentTimelineBuilderToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Timeline Builder graph.

    Flow:
        collect_events -> correlate_sources
        -> build_timeline -> identify_root_cause
        -> generate_narrative -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_events(
            _to_dict(state),
            toolkit,
        )

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_sources(
            _to_dict(state),
            toolkit,
        )

    async def _timeline(
        state: Any,
    ) -> dict[str, Any]:
        return await build_timeline(
            _to_dict(state),
            toolkit,
        )

    async def _root_cause(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_root_cause(
            _to_dict(state),
            toolkit,
        )

    async def _narrative(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_narrative(
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

    graph = StateGraph(IncidentTimelineBuilderState)
    graph.add_node("collect_events", _collect)
    graph.add_node("correlate_sources", _correlate)
    graph.add_node("build_timeline", _timeline)
    graph.add_node(
        "identify_root_cause",
        _root_cause,
    )
    graph.add_node(
        "generate_narrative",
        _narrative,
    )
    graph.add_node("report", _report)

    graph.set_entry_point("collect_events")
    graph.add_edge(
        "collect_events",
        "correlate_sources",
    )
    graph.add_edge(
        "correlate_sources",
        "build_timeline",
    )
    graph.add_edge(
        "build_timeline",
        "identify_root_cause",
    )
    graph.add_edge(
        "identify_root_cause",
        "generate_narrative",
    )
    graph.add_edge(
        "generate_narrative",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_incident_timeline_builder_graph(
    siem_client: Any | None = None,
    edr_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Incident Timeline Builder graph."""
    toolkit = IncidentTimelineBuilderToolkit(
        siem_client=siem_client,
        edr_client=edr_client,
    )
    return build_graph(toolkit)
