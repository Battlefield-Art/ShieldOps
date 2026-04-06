"""Phishing Email Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import PhishingEmailAnalyzerState
from .nodes import (
    analyze_content,
    analyze_sender,
    analyze_urls,
    generate_report,
    ingest_email,
    score_risk,
)
from .tools import PhishingEmailAnalyzerToolkit


def build_graph(toolkit: PhishingEmailAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the phishing_email_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        PhishingEmailAnalyzerState,
        [
            ("ingest_email", ingest_email),
            ("analyze_sender", analyze_sender),
            ("analyze_urls", analyze_urls),
            ("analyze_content", analyze_content),
            ("score_risk", score_risk),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_phishing_email_analyzer_graph(
    url_scanner: Any | None = None,
    reputation_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Phishing Email Analyzer graph."""
    toolkit = PhishingEmailAnalyzerToolkit(
        url_scanner=url_scanner,
        reputation_client=reputation_client,
    )
    return build_graph(toolkit)
