"""Anomaly Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AnomalyDetectorState
from .nodes import (
    classify_anomalies,
    collect_data,
    correlate_anomalies,
    detect_anomalies,
    generate_report,
    send_alerts,
)
from .tools import AnomalyDetectorToolkit


def build_graph(toolkit: AnomalyDetectorToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Anomaly Detector agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_data(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_anomalies(_to_dict(state), toolkit)

    async def _correlate(state: Any) -> dict[str, Any]:
        return await correlate_anomalies(_to_dict(state), toolkit)

    async def _alert(state: Any) -> dict[str, Any]:
        return await send_alerts(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(AnomalyDetectorState)
    graph.add_node("collect_data", _collect)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("classify", _classify)
    graph.add_node("correlate", _correlate)
    graph.add_node("alert", _alert)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_data")
    graph.add_edge("collect_data", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify")
    graph.add_edge("classify", "correlate")
    graph.add_edge("correlate", "alert")
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph


def create_anomaly_detector_graph(
    metric_client: Any | None = None,
    log_client: Any | None = None,
    trace_client: Any | None = None,
    alert_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Anomaly Detector agent graph with dependencies."""
    toolkit = AnomalyDetectorToolkit(
        metric_client=metric_client,
        log_client=log_client,
        trace_client=trace_client,
        alert_client=alert_client,
    )
    return build_graph(toolkit)
