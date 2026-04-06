"""Incident Timeline Builder Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: IncidentTimelineBuilderToolkit):  # type: ignore[no-untyped-def]
    """Build the incident_timeline_builder agent graph (linear sequence)."""
    return build_linear_graph(
        IncidentTimelineBuilderState,
        [
            ("collect_events", collect_events),
            ("correlate_sources", correlate_sources),
            ("build_timeline", build_timeline),
            ("identify_root_cause", identify_root_cause),
            ("generate_narrative", generate_narrative),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
