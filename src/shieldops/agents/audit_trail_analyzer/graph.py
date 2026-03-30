"""Audit Trail Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

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

_AGENT = "audit_trail_analyzer"


def _check_error(
    state: AuditTrailAnalyzerState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: AuditTrailAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Audit Trail Analyzer graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_logs(
            _to_dict(state),
            toolkit,
        )

    async def _normalize(
        state: Any,
    ) -> dict[str, Any]:
        return await normalize_events(
            _to_dict(state),
            toolkit,
        )

    async def _anomalies(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_activities(
            _to_dict(state),
            toolkit,
        )

    async def _findings(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_findings(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(AuditTrailAnalyzerState)
    graph.add_node(
        "collect_logs",
        traced_node("ata.collect", _AGENT)(_collect),
    )
    graph.add_node(
        "normalize_events",
        traced_node("ata.normalize", _AGENT)(_normalize),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("ata.anomalies", _AGENT)(_anomalies),
    )
    graph.add_node(
        "correlate_activities",
        traced_node("ata.correlate", _AGENT)(_correlate),
    )
    graph.add_node(
        "generate_findings",
        traced_node("ata.findings", _AGENT)(_findings),
    )
    graph.add_node(
        "report",
        traced_node("ata.report", _AGENT)(_report),
    )

    graph.set_entry_point("collect_logs")
    graph.add_edge("collect_logs", "normalize_events")
    graph.add_edge(
        "normalize_events",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "correlate_activities",
    )
    graph.add_edge(
        "correlate_activities",
        "generate_findings",
    )
    graph.add_edge("generate_findings", "report")
    graph.add_edge("report", END)

    return graph


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
