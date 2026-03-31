"""Event Stream Processor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import EventStreamProcessorState
from .nodes import (
    connect_streams,
    correlate,
    enrich,
    generate_report,
    parse_events,
    route,
)
from .tools import EventStreamProcessorToolkit

_AGENT = "event_stream_processor"


# ------------------------------------------------------------------
# Conditional edge routing functions
# ------------------------------------------------------------------


def _should_parse(
    state: EventStreamProcessorState,
) -> str:
    """Skip parse_events if no streams connected; otherwise proceed."""
    if not state.stream_connections:
        return "report"
    return "parse_events"


def _should_route(
    state: EventStreamProcessorState,
) -> str:
    """Skip routing if no correlations fired; otherwise proceed."""
    if not state.correlations:
        return "report"
    return "route"


# ------------------------------------------------------------------
# Graph builder
# ------------------------------------------------------------------


def build_graph(
    toolkit: EventStreamProcessorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Event Stream Processor LangGraph workflow.

    Flow:
        connect_streams --(no streams? skip)--> report
        connect_streams --> parse_events --> enrich --> correlate
        correlate --(no correlations? skip)--> report
        correlate --> route --> report --> END
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _connect(state: Any) -> dict[str, Any]:
        return await connect_streams(_to_dict(state), toolkit)

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_events(_to_dict(state), toolkit)

    async def _enrich(state: Any) -> dict[str, Any]:
        return await enrich(_to_dict(state), toolkit)

    async def _correlate(state: Any) -> dict[str, Any]:
        return await correlate(_to_dict(state), toolkit)

    async def _route(state: Any) -> dict[str, Any]:
        return await route(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(EventStreamProcessorState)

    graph.add_node(
        "connect_streams",
        traced_node(f"{_AGENT}.connect_streams", _AGENT)(_connect),
    )
    graph.add_node(
        "parse_events",
        traced_node(f"{_AGENT}.parse_events", _AGENT)(_parse),
    )
    graph.add_node(
        "enrich",
        traced_node(f"{_AGENT}.enrich", _AGENT)(_enrich),
    )
    graph.add_node(
        "correlate",
        traced_node(f"{_AGENT}.correlate", _AGENT)(_correlate),
    )
    graph.add_node(
        "route",
        traced_node(f"{_AGENT}.route", _AGENT)(_route),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(_report),
    )

    # Entry point
    graph.set_entry_point("connect_streams")

    # Conditional: skip parse if no streams connected
    graph.add_conditional_edges(
        "connect_streams",
        _should_parse,
        {
            "parse_events": "parse_events",
            "report": "report",
        },
    )

    # Linear edges: parse -> enrich -> correlate
    graph.add_edge("parse_events", "enrich")
    graph.add_edge("enrich", "correlate")

    # Conditional: skip routing if no correlations found
    graph.add_conditional_edges(
        "correlate",
        _should_route,
        {
            "route": "route",
            "report": "report",
        },
    )

    graph.add_edge("route", "report")
    graph.add_edge("report", END)

    return graph


def create_event_stream_processor_graph(
    kafka_client: Any | None = None,
    threat_intel_api: Any | None = None,
    siem_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Event Stream Processor graph."""
    toolkit = EventStreamProcessorToolkit(
        kafka_client=kafka_client,
        threat_intel_api=threat_intel_api,
        siem_client=siem_client,
    )
    return build_graph(toolkit)
