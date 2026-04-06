"""Evidence Automation Engine Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import EvidenceAutomationEngineState
from .nodes import (
    collect_evidence,
    identify_requirements,
    package_evidence,
    report,
    submit_attestation,
    validate_artifacts,
)
from .tools import EvidenceAutomationEngineToolkit


def build_graph(toolkit: EvidenceAutomationEngineToolkit):  # type: ignore[no-untyped-def]
    """Build the evidence_automation_engine agent graph (linear sequence)."""
    return build_linear_graph(
        EvidenceAutomationEngineState,
        [
            ("identify_requirements", identify_requirements),
            ("collect_evidence", collect_evidence),
            ("validate_artifacts", validate_artifacts),
            ("package_evidence", package_evidence),
            ("submit_attestation", submit_attestation),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_evidence_automation_engine_graph(
    evidence_store: Any | None = None,
    scanner: Any | None = None,
    attestation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Evidence Automation Engine graph."""
    toolkit = EvidenceAutomationEngineToolkit(
        evidence_store=evidence_store,
        scanner=scanner,
        attestation_api=attestation_api,
    )
    return build_graph(toolkit)
