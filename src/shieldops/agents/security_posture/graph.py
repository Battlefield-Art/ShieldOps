"""Security Posture Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityPostureState
from .nodes import (
    assess_domains,
    generate_report,
    identify_gaps,
    prioritize_remediation,
)
from .tools import SecurityPostureToolkit


def build_graph(toolkit: SecurityPostureToolkit):  # type: ignore[no-untyped-def]
    """Build the security_posture agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityPostureState,
        [
            ("assess_domains", assess_domains),
            ("identify_gaps", identify_gaps),
            ("prioritize_remediation", prioritize_remediation),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_posture_graph(
    rba_client: Any | None = None,
    compliance_store: Any | None = None,
    vuln_scanner: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Posture Manager agent graph with dependencies."""
    toolkit = SecurityPostureToolkit(
        rba_client=rba_client,
        compliance_store=compliance_store,
        vuln_scanner=vuln_scanner,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
