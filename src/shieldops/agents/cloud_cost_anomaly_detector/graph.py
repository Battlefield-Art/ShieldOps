"""Cloud Cost Anomaly Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: CloudCostAnomalyDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_cost_anomaly_detector agent graph (linear sequence)."""
    return build_linear_graph(
        CloudCostAnomalyDetectorState,
        [
            ("collect_billing", collect_billing),
            ("analyze_trends", analyze_trends),
            ("detect_anomalies", detect_anomalies),
            ("classify_cause", classify_cause),
            ("send_alerts", send_alerts),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
