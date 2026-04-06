"""SOAR Workflow Orchestrator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SOARWorkflowState
from .nodes import (
    enrich_context,
    execute_containment,
    execute_eradication,
    intake_and_classify,
    recover_and_report,
)
from .tools import SOARWorkflowToolkit


def build_graph(toolkit: SOARWorkflowToolkit):  # type: ignore[no-untyped-def]
    """Build the soar_workflow agent graph (linear sequence)."""
    return build_linear_graph(
        SOARWorkflowState,
        [
            ("intake_and_classify", intake_and_classify),
            ("enrich_context", enrich_context),
            ("execute_containment", execute_containment),
            ("execute_eradication", execute_eradication),
            ("recover_and_report", recover_and_report),
        ],
        toolkit=toolkit,
    )


def create_soar_workflow_graph(
    siem_client: Any | None = None,
    edr_client: Any | None = None,
    firewall_client: Any | None = None,
    threat_intel_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SOAR Workflow Orchestrator agent graph with dependencies."""
    toolkit = SOARWorkflowToolkit(
        siem_client=siem_client,
        edr_client=edr_client,
        firewall_client=firewall_client,
        threat_intel_client=threat_intel_client,
    )
    return build_graph(toolkit)
