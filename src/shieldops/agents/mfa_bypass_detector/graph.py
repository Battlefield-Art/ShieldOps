"""MFA Bypass Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import MFABypassDetectorState
from .nodes import (
    analyze_patterns,
    apply_remediation,
    assess_risk,
    collect_auth_events,
    detect_mfa_bypass,
    generate_report,
)
from .tools import MFABypassDetectorToolkit


def build_graph(
    toolkit: MFABypassDetectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the MFA Bypass Detector graph.

    Flow:
        collect_auth_events -> analyze_patterns
        -> detect_bypass -> assess_risk
        -> remediate -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_auth_events(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_mfa_bypass(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(
            _to_dict(state),
            toolkit,
        )

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await apply_remediation(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(MFABypassDetectorState)
    graph.add_node("collect_auth_events", _collect)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("detect_bypass", _detect)
    graph.add_node("assess_risk", _assess)
    graph.add_node("remediate", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_auth_events")
    graph.add_edge(
        "collect_auth_events",
        "analyze_patterns",
    )
    graph.add_edge(
        "analyze_patterns",
        "detect_bypass",
    )
    graph.add_edge(
        "detect_bypass",
        "assess_risk",
    )
    graph.add_edge(
        "assess_risk",
        "remediate",
    )
    graph.add_edge(
        "remediate",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_mfa_bypass_detector_graph(
    identity_provider: Any | None = None,
    siem_connector: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the MFA Bypass Detector graph."""
    toolkit = MFABypassDetectorToolkit(
        identity_provider=identity_provider,
        siem_connector=siem_connector,
    )
    return build_graph(toolkit)
