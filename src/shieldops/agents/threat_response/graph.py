"""Threat Response Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ThreatResponseState
from .nodes import (
    classify_threat,
    execute_containment,
    execute_eradication,
    generate_report,
    select_playbook,
    verify_remediation,
)
from .tools import ThreatResponseToolkit


def build_graph(toolkit: ThreatResponseToolkit):  # type: ignore[no-untyped-def]
    """Build the threat_response agent graph (linear sequence)."""
    return build_linear_graph(
        ThreatResponseState,
        [
            ("classify_threat", classify_threat),
            ("select_playbook", select_playbook),
            ("execute_containment", execute_containment),
            ("execute_eradication", execute_eradication),
            ("verify_remediation", verify_remediation),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_threat_response_graph(
    soar_client: Any | None = None,
    edr_client: Any | None = None,
    firewall_client: Any | None = None,
    identity_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Threat Response agent graph with dependencies."""
    toolkit = ThreatResponseToolkit(
        soar_client=soar_client,
        edr_client=edr_client,
        firewall_client=firewall_client,
        identity_client=identity_client,
    )
    return build_graph(toolkit)
