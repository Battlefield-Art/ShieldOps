"""DNS Firewall Controller Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DNSFirewallControllerState
from .nodes import (
    analyze_domains,
    check_reputation,
    detect_tunneling,
    enforce_policy,
    generate_report,
    ingest_queries,
)
from .tools import DNSFirewallControllerToolkit


def build_graph(toolkit: DNSFirewallControllerToolkit):  # type: ignore[no-untyped-def]
    """Build the dns_firewall_controller agent graph (linear sequence)."""
    return build_linear_graph(
        DNSFirewallControllerState,
        [
            ("ingest_queries", ingest_queries),
            ("analyze_domains", analyze_domains),
            ("check_reputation", check_reputation),
            ("detect_tunneling", detect_tunneling),
            ("enforce_policy", enforce_policy),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_dns_firewall_controller_graph(
    dns_source: Any | None = None,
    reputation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Firewall Controller graph."""
    toolkit = DNSFirewallControllerToolkit(
        dns_source=dns_source,
        reputation_api=reputation_api,
    )
    return build_graph(toolkit)
