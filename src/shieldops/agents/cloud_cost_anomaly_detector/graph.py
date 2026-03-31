"""Cloud Cost Anomaly Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudCostAnomalyDetectorState
from .nodes import (
    analyze_trends,
    classify_cause,
    collect_billing,
    detect_anomalies,
    generate_report,
    send_alerts,
)
from .tools import CloudCostAnomalyDetectorToolkit


def build_graph(
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Cost Anomaly Detector graph.

    Flow:
        collect_billing -> analyze_trends
        -> detect_anomalies -> classify_cause
        -> send_alerts -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_billing(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_trends(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_cause(
            _to_dict(state),
            toolkit,
        )

    async def _alert(
        state: Any,
    ) -> dict[str, Any]:
        return await send_alerts(
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

    graph = StateGraph(CloudCostAnomalyDetectorState)
    graph.add_node("collect_billing", _collect)
    graph.add_node("analyze_trends", _analyze)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("classify_cause", _classify)
    graph.add_node("send_alerts", _alert)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_billing")
    graph.add_edge(
        "collect_billing",
        "analyze_trends",
    )
    graph.add_edge(
        "analyze_trends",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "classify_cause",
    )
    graph.add_edge(
        "classify_cause",
        "send_alerts",
    )
    graph.add_edge(
        "send_alerts",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_cost_anomaly_detector_graph(
    billing_api: Any | None = None,
    alert_channel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Cost Anomaly Detector graph."""
    toolkit = CloudCostAnomalyDetectorToolkit(
        billing_api=billing_api,
        alert_channel=alert_channel,
    )
    return build_graph(toolkit)
