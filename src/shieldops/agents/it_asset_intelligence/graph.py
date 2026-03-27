"""IT Asset Intelligence Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: ITAssetIntelligenceToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the IT Asset Intelligence agent graph.

    Flow:
        discover_assets -> classify_criticality
        -> assess_security_posture
        -> correlate_with_threats
        -> generate_risk_report -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_assets(_to_dict(state), toolkit)

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_criticality(_to_dict(state), toolkit)

    async def _posture(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_security_posture(_to_dict(state), toolkit)

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_with_threats(_to_dict(state), toolkit)

    async def _risk(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_risk_report(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(ITAssetIntelligenceState)
    graph.add_node("discover_assets", _discover)
    graph.add_node("classify_criticality", _classify)
    graph.add_node("assess_security_posture", _posture)
    graph.add_node("correlate_with_threats", _correlate)
    graph.add_node("generate_risk_report", _risk)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_assets")
    graph.add_edge("discover_assets", "classify_criticality")
    graph.add_edge(
        "classify_criticality",
        "assess_security_posture",
    )
    graph.add_edge(
        "assess_security_posture",
        "correlate_with_threats",
    )
    graph.add_edge(
        "correlate_with_threats",
        "generate_risk_report",
    )
    graph.add_edge("generate_risk_report", "report")
    graph.add_edge("report", END)

    return graph


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
