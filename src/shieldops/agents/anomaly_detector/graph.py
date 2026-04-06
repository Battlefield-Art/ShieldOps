"""Anomaly Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: AnomalyDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the anomaly_detector agent graph (linear sequence)."""
    return build_linear_graph(
        AnomalyDetectorState,
        [
            ("collect_data", collect_data),
            ("detect_anomalies", detect_anomalies),
            ("classify", classify_anomalies),
            ("correlate", correlate_anomalies),
            ("alert", send_alerts),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
