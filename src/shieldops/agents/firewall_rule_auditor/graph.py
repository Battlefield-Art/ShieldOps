"""Firewall Rule Auditor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import FirewallAuditState
from .nodes import (
    check_compliance,
    classify_risks,
    collect_rules,
    detect_violations,
    generate_report,
    recommend_fixes,
)
from .tools import FirewallAuditToolkit


def build_graph(toolkit: FirewallAuditToolkit):  # type: ignore[no-untyped-def]
    """Build the firewall_rule_auditor agent graph (linear sequence)."""
    return build_linear_graph(
        FirewallAuditState,
        [
            ("collect_rules", collect_rules),
            ("detect_violations", detect_violations),
            ("classify_risks", classify_risks),
            ("check_compliance", check_compliance),
            ("recommend_fixes", recommend_fixes),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_firewall_rule_auditor_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Firewall Rule Auditor agent graph with dependencies."""
    toolkit = FirewallAuditToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
