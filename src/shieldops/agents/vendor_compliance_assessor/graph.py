"""Vendor Compliance Assessor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import VendorComplianceAssessorState
from .nodes import (
    assess_risk,
    collect_questionnaires,
    generate_report,
    inventory_vendors,
    report,
    score_compliance,
)
from .tools import VendorComplianceAssessorToolkit


def build_graph(toolkit: VendorComplianceAssessorToolkit):  # type: ignore[no-untyped-def]
    """Build the vendor_compliance_assessor agent graph (linear sequence)."""
    return build_linear_graph(
        VendorComplianceAssessorState,
        [
            ("inventory_vendors", inventory_vendors),
            ("collect_questionnaires", collect_questionnaires),
            ("assess_risk", assess_risk),
            ("score_compliance", score_compliance),
            ("generate_report", generate_report),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_vendor_compliance_assessor_graph(
    vendor_db: Any | None = None,
    questionnaire_api: Any | None = None,
    risk_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Vendor Compliance Assessor graph."""
    toolkit = VendorComplianceAssessorToolkit(
        vendor_db=vendor_db,
        questionnaire_api=questionnaire_api,
        risk_engine=risk_engine,
    )
    return build_graph(toolkit)
