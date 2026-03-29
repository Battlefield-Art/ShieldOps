"""Cloud Audit Logger Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudAuditLoggerState
from .nodes import (
    assess_risk,
    correlate_activity,
    detect_anomalies,
    ingest_logs,
)
from .tools import CloudAuditLoggerToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: CloudAuditLoggerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Audit Logger agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_logs(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _correlate(state: Any) -> dict[str, Any]:
        return await correlate_activity(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    graph = StateGraph(CloudAuditLoggerState)

    graph.add_node("ingest_logs", _ingest)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("correlate_activity", _correlate)
    graph.add_node("assess_risk", _assess)

    graph.set_entry_point("ingest_logs")
    graph.add_conditional_edges(
        "ingest_logs",
        _has_error,
        {"end": END, "continue": "detect_anomalies"},
    )
    graph.add_edge("detect_anomalies", "correlate_activity")
    graph.add_edge("correlate_activity", "assess_risk")
    graph.add_edge("assess_risk", END)

    return graph


def create_cloud_audit_logger_graph(
    log_clients: Any | None = None,
    siem_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Audit Logger agent graph."""
    toolkit = CloudAuditLoggerToolkit(
        log_clients=log_clients,
        siem_client=siem_client,
    )
    return build_graph(toolkit)
