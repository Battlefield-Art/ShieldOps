"""Bandwidth Anomaly Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import BandwidthAnomalyDetectorState
from .nodes import (
    build_baselines,
    classify_traffic,
    collect_samples,
    detect_anomalies,
    generate_report,
    send_alerts,
)
from .tools import BandwidthAnomalyDetectorToolkit


def build_graph(
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Bandwidth Anomaly Detector agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_samples(_to_dict(state), toolkit)

    async def _baselines(state: Any) -> dict[str, Any]:
        return await build_baselines(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_traffic(_to_dict(state), toolkit)

    async def _alert(state: Any) -> dict[str, Any]:
        return await send_alerts(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(BandwidthAnomalyDetectorState)
    graph.add_node("collect_samples", _collect)
    graph.add_node("build_baselines", _baselines)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("classify_traffic", _classify)
    graph.add_node("alert", _alert)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_samples")
    graph.add_edge("collect_samples", "build_baselines")
    graph.add_edge("build_baselines", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_traffic")
    graph.add_edge("classify_traffic", "alert")
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph


def create_bandwidth_anomaly_detector_graph(
    netflow_client: Any | None = None,
    firewall_client: Any | None = None,
    alert_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Bandwidth Anomaly Detector graph with deps."""
    toolkit = BandwidthAnomalyDetectorToolkit(
        netflow_client=netflow_client,
        firewall_client=firewall_client,
        alert_client=alert_client,
    )
    return build_graph(toolkit)
