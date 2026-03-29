"""Email DLP Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EmailDLPMonitorState
from .nodes import (
    analyze_attachments,
    audit_log,
    detect_pii,
    enforce_policy,
    generate_report,
    scan_outbound,
)
from .tools import EmailDLPMonitorToolkit


def build_graph(
    toolkit: EmailDLPMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Email DLP Monitor graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_outbound(_to_dict(state), toolkit)

    async def _pii(state: Any) -> dict[str, Any]:
        return await detect_pii(_to_dict(state), toolkit)

    async def _attachments(state: Any) -> dict[str, Any]:
        return await analyze_attachments(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policy(_to_dict(state), toolkit)

    async def _audit(state: Any) -> dict[str, Any]:
        return await audit_log(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(EmailDLPMonitorState)
    graph.add_node("scan_outbound", _scan)
    graph.add_node("detect_pii", _pii)
    graph.add_node("analyze_attachments", _attachments)
    graph.add_node("enforce_policy", _enforce)
    graph.add_node("audit_log", _audit)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("scan_outbound")
    graph.add_edge("scan_outbound", "detect_pii")
    graph.add_edge("detect_pii", "analyze_attachments")
    graph.add_edge("analyze_attachments", "enforce_policy")
    graph.add_edge("enforce_policy", "audit_log")
    graph.add_edge("audit_log", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_email_dlp_monitor_graph(
    dlp_client: Any | None = None,
    policy_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Email DLP Monitor graph."""
    toolkit = EmailDLPMonitorToolkit(
        dlp_client=dlp_client,
        policy_client=policy_client,
    )
    return build_graph(toolkit)
