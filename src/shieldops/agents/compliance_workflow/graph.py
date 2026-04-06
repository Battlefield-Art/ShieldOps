"""Compliance Workflow Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ComplianceWorkflowState
from .nodes import (
    assess_gaps,
    collect_evidence,
    generate_remediation,
    generate_report,
    identify_frameworks,
    map_controls,
)
from .tools import ComplianceWorkflowToolkit


def build_graph(toolkit: ComplianceWorkflowToolkit):  # type: ignore[no-untyped-def]
    """Build the compliance_workflow agent graph (linear sequence)."""
    return build_linear_graph(
        ComplianceWorkflowState,
        [
            ("identify_frameworks", identify_frameworks),
            ("map_controls", map_controls),
            ("collect_evidence", collect_evidence),
            ("assess_gaps", assess_gaps),
            ("generate_remediation", generate_remediation),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_compliance_workflow_graph(
    compliance_backend: Any | None = None,
    evidence_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create a Compliance Workflow graph."""
    toolkit = ComplianceWorkflowToolkit(
        compliance_backend=compliance_backend,
        evidence_store=evidence_store,
    )
    return build_graph(toolkit)
