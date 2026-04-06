"""Email DLP Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: EmailDLPMonitorToolkit):  # type: ignore[no-untyped-def]
    """Build the email_dlp_monitor agent graph (linear sequence)."""
    return build_linear_graph(
        EmailDLPMonitorState,
        [
            ("scan_outbound", scan_outbound),
            ("detect_pii", detect_pii),
            ("analyze_attachments", analyze_attachments),
            ("enforce_policy", enforce_policy),
            ("audit_log", audit_log),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


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
