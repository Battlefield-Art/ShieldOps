"""Change Risk Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ChangeRiskAnalyzerState
from .nodes import (
    analyze_diff,
    assess_risk,
    collect_change,
    generate_report,
    predict_blast_radius,
    recommend,
)
from .tools import ChangeRiskAnalyzerToolkit


def build_graph(toolkit: ChangeRiskAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the change_risk_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        ChangeRiskAnalyzerState,
        [
            ("collect_change", collect_change),
            ("analyze_diff", analyze_diff),
            ("assess_risk", assess_risk),
            ("predict_blast_radius", predict_blast_radius),
            ("recommend", recommend),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_change_risk_analyzer_graph(
    git_client: Any | None = None,
    deployment_db: Any | None = None,
    incident_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Change Risk Analyzer agent graph with dependencies."""
    toolkit = ChangeRiskAnalyzerToolkit(
        git_client=git_client,
        deployment_db=deployment_db,
        incident_db=incident_db,
    )
    return build_graph(toolkit)
