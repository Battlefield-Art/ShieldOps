"""Endpoint Behavior Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EndpointBehaviorMonitorState
from .nodes import analyze_behavior, collect_telemetry, correlate_signals
from .tools import EndpointBehaviorMonitorToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: EndpointBehaviorMonitorToolkit,
) -> Any:
    async def _wrapper(state: Any) -> dict[str, Any]:
        d = state.model_dump() if hasattr(state, "model_dump") else dict(state)
        try:
            return await func(d, toolkit)
        except Exception as exc:
            return {"error": str(exc)}

    return _wrapper


def _check_error(state: Any) -> str:
    err = state.error if hasattr(state, "error") else state.get("error", "")
    return "error_end" if err else "continue"


def build_graph(
    toolkit: EndpointBehaviorMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Endpoint Behavior Monitor agent graph."""

    graph = StateGraph(EndpointBehaviorMonitorState)

    graph.add_node(
        "collect_telemetry",
        _traced_node(collect_telemetry, toolkit),
    )
    graph.add_node(
        "analyze_behavior",
        _traced_node(analyze_behavior, toolkit),
    )
    graph.add_node(
        "correlate_signals",
        _traced_node(correlate_signals, toolkit),
    )
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("collect_telemetry")
    graph.add_conditional_edges(
        "collect_telemetry",
        _check_error,
        {"continue": "analyze_behavior", "error_end": "error_end"},
    )
    graph.add_conditional_edges(
        "analyze_behavior",
        _check_error,
        {"continue": "correlate_signals", "error_end": "error_end"},
    )
    graph.add_edge("correlate_signals", END)
    graph.add_edge("error_end", END)

    return graph


def create_endpoint_behavior_monitor_graph(
    edr_client: Any | None = None,
    siem_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Behavior Monitor graph with deps."""
    toolkit = EndpointBehaviorMonitorToolkit(
        edr_client=edr_client,
        siem_client=siem_client,
    )
    return build_graph(toolkit)
