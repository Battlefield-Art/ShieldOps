"""Compliance Gap Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ComplianceGapAnalyzerState
from .nodes import (
    build_report,
    generate_plan,
    identify_gaps,
    map_requirements,
    prioritize_risks,
    scan_posture,
)
from .tools import ComplianceGapAnalyzerToolkit


def build_graph(toolkit: ComplianceGapAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the compliance_gap_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        ComplianceGapAnalyzerState,
        [
            ("scan_posture", scan_posture),
            ("map_requirements", map_requirements),
            ("identify_gaps", identify_gaps),
            ("prioritize_risks", prioritize_risks),
            ("generate_plan", generate_plan),
            ("build_report", build_report),
        ],
        toolkit=toolkit,
    )


def create_compliance_gap_analyzer_graph(
    toolkit: ComplianceGapAnalyzerToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory for the Compliance Gap Analyzer."""
    if toolkit is None:
        toolkit = ComplianceGapAnalyzerToolkit()
    return build_graph(toolkit)
