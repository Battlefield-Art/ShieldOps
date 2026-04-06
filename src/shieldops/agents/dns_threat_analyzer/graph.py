"""DNS Threat Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DNSThreatAnalyzerState
from .nodes import (
    analyze_patterns,
    classify_domains,
    collect_dns_logs,
    detect_threats,
    enforce_blocks,
    generate_report,
)
from .tools import DNSThreatAnalyzerToolkit


def build_graph(toolkit: DNSThreatAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the dns_threat_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        DNSThreatAnalyzerState,
        [
            ("collect_dns_logs", collect_dns_logs),
            ("analyze_patterns", analyze_patterns),
            ("detect_threats", detect_threats),
            ("classify_domains", classify_domains),
            ("enforce_blocks", enforce_blocks),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_dns_threat_analyzer_graph(
    dns_log_source: Any | None = None,
    threat_intel_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Threat Analyzer graph."""
    toolkit = DNSThreatAnalyzerToolkit(
        dns_log_source=dns_log_source,
        threat_intel_api=threat_intel_api,
    )
    return build_graph(toolkit)
