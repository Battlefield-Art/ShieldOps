"""IT Asset Intelligence Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ITAssetIntelligenceState
from .nodes import (
    assess_security_posture,
    classify_criticality,
    correlate_with_threats,
    discover_assets,
    generate_risk_report,
    report,
)
from .tools import ITAssetIntelligenceToolkit


def build_graph(toolkit: ITAssetIntelligenceToolkit):  # type: ignore[no-untyped-def]
    """Build the it_asset_intelligence agent graph (linear sequence)."""
    return build_linear_graph(
        ITAssetIntelligenceState,
        [
            ("discover_assets", discover_assets),
            ("classify_criticality", classify_criticality),
            ("assess_security_posture", assess_security_posture),
            ("correlate_with_threats", correlate_with_threats),
            ("generate_risk_report", generate_risk_report),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_it_asset_intelligence_graph(
    cmdb_client: Any | None = None,
    threat_intel: Any | None = None,
    vuln_scanner: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the IT Asset Intelligence graph."""
    toolkit = ITAssetIntelligenceToolkit(
        cmdb_client=cmdb_client,
        threat_intel=threat_intel,
        vuln_scanner=vuln_scanner,
    )
    return build_graph(toolkit)
