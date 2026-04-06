"""Bandwidth Anomaly Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: BandwidthAnomalyDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the bandwidth_anomaly_detector agent graph (linear sequence)."""
    return build_linear_graph(
        BandwidthAnomalyDetectorState,
        [
            ("collect_samples", collect_samples),
            ("build_baselines", build_baselines),
            ("detect_anomalies", detect_anomalies),
            ("classify_traffic", classify_traffic),
            ("alert", send_alerts),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
