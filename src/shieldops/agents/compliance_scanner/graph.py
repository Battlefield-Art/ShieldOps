"""Compliance Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ComplianceScannerState
from .nodes import (
    evaluate_findings,
    generate_evidence,
    generate_report,
    scan_controls,
    select_frameworks,
    track_remediation,
)
from .tools import ComplianceScannerToolkit


def build_graph(toolkit: ComplianceScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the compliance_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        ComplianceScannerState,
        [
            ("select_frameworks", select_frameworks),
            ("scan_controls", scan_controls),
            ("evaluate_findings", evaluate_findings),
            ("track_remediation", track_remediation),
            ("generate_evidence", generate_evidence),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_compliance_scanner_graph(
    policy_client: Any | None = None,
    config_client: Any | None = None,
    evidence_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Compliance Scanner agent graph with dependencies."""
    toolkit = ComplianceScannerToolkit(
        policy_client=policy_client,
        config_client=config_client,
        evidence_store=evidence_store,
    )
    return build_graph(toolkit)
