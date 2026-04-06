"""DNS Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DNSSecurityState
from .nodes import (
    collect_dns,
    detect_dga,
    detect_tunneling,
    detect_typosquatting,
    generate_report,
    respond_to_threats,
)
from .tools import DNSSecurityToolkit


def build_graph(toolkit: DNSSecurityToolkit):  # type: ignore[no-untyped-def]
    """Build the dns_security agent graph (linear sequence)."""
    return build_linear_graph(
        DNSSecurityState,
        [
            ("collect_dns", collect_dns),
            ("detect_tunneling", detect_tunneling),
            ("detect_dga", detect_dga),
            ("detect_typosquatting", detect_typosquatting),
            ("respond", respond_to_threats),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_dns_security_graph(
    dns_log_client: Any | None = None,
    threat_intel_client: Any | None = None,
    firewall_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Security agent graph with dependencies."""
    toolkit = DNSSecurityToolkit(
        dns_log_client=dns_log_client,
        threat_intel_client=threat_intel_client,
        firewall_client=firewall_client,
    )
    return build_graph(toolkit)
