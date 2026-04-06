"""Audit Trail Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AuditTrailAnalyzerState
from .nodes import (
    collect_logs,
    correlate_activities,
    detect_anomalies,
    generate_findings,
    normalize_events,
    report,
)
from .tools import AuditTrailAnalyzerToolkit


def build_graph(toolkit: AuditTrailAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the audit_trail_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        AuditTrailAnalyzerState,
        [
            ("collect_logs", collect_logs),
            ("normalize_events", normalize_events),
            ("detect_anomalies", detect_anomalies),
            ("correlate_activities", correlate_activities),
            ("generate_findings", generate_findings),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_audit_trail_analyzer_graph(
    log_collector: Any | None = None,
    anomaly_engine: Any | None = None,
    correlation_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Audit Trail Analyzer graph."""
    toolkit = AuditTrailAnalyzerToolkit(
        log_collector=log_collector,
        anomaly_engine=anomaly_engine,
        correlation_engine=correlation_engine,
    )
    return build_graph(toolkit)
