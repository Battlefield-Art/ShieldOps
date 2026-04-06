"""Email Gateway Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import GatewayAnalyzerState
from .nodes import (
    analyze_headers,
    check_reputation,
    collect_records,
    detect_spoofing,
    generate_report,
    validate_auth,
)
from .tools import EmailGatewayAnalyzerToolkit


def build_graph(toolkit: EmailGatewayAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the email_gateway_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        GatewayAnalyzerState,
        [
            ("collect_records", collect_records),
            ("validate_auth", validate_auth),
            ("analyze_headers", analyze_headers),
            ("check_reputation", check_reputation),
            ("detect_spoofing", detect_spoofing),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_email_gateway_analyzer_graph(
    dns_client: Any | None = None,
    reputation_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Email Gateway Analyzer graph."""
    toolkit = EmailGatewayAnalyzerToolkit(
        dns_client=dns_client,
        reputation_client=reputation_client,
    )
    return build_graph(toolkit)
