"""SLA Violation Detector — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SLAViolationDetectorState
from .nodes import (
    calculate_impact,
    collect_metrics,
    detect_violations,
    evaluate_thresholds,
    notify_owners,
    report,
)
from .tools import SLAViolationDetectorToolkit


def build_graph(toolkit: SLAViolationDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the sla_violation_detector agent graph (linear sequence)."""
    return build_linear_graph(
        SLAViolationDetectorState,
        [
            ("collect_metrics", collect_metrics),
            ("evaluate_thresholds", evaluate_thresholds),
            ("detect_violations", detect_violations),
            ("calculate_impact", calculate_impact),
            ("notify_owners", notify_owners),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_sla_violation_detector_graph(
    metrics_service: Any | None = None,
    notification_service: Any | None = None,
) -> StateGraph:
    """Factory to create the SLA violation detector."""
    toolkit = SLAViolationDetectorToolkit(
        metrics_service=metrics_service,
        notification_service=notification_service,
    )
    return build_graph(toolkit)
