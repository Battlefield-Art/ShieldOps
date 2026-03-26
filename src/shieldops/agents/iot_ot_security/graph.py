"""IoT/OT Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import IoTOTSecurityState, ThreatLevel
from .nodes import (
    assess_vulnerabilities,
    detect_anomalies,
    discover_devices,
    enforce_segmentation,
    generate_report,
    profile_behavior,
)
from .tools import IoTOTSecurityToolkit

# Threat levels requiring immediate segmentation
_CRITICAL_THREATS = {
    ThreatLevel.CRITICAL.value,
    ThreatLevel.HIGH.value,
}


def _needs_segmentation(state: Any) -> str:
    """Route based on whether critical threats found."""
    if hasattr(state, "anomalies_detected"):
        anomalies = state.anomalies_detected
        vulns = state.vulnerabilities_found
    else:
        anomalies = state.get(
            "anomalies_detected",
            [],
        )
        vulns = state.get(
            "vulnerabilities_found",
            [],
        )

    # Check for critical anomalies
    for a in anomalies:
        level = a.get("threat_level", "") if isinstance(a, dict) else a.threat_level
        if level in _CRITICAL_THREATS:
            return "enforce_segmentation"

    # Check for critical exploitable vulns
    for v in vulns:
        sev = v.get("severity", "") if isinstance(v, dict) else v.severity
        exploitable = v.get("exploitable", False) if isinstance(v, dict) else v.exploitable
        if sev == ThreatLevel.CRITICAL.value and exploitable:
            return "enforce_segmentation"

    return "report"


def build_graph(
    toolkit: IoTOTSecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the IoT/OT Security graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_devices(
            _to_dict(state),
            toolkit,
        )

    async def _profile(
        state: Any,
    ) -> dict[str, Any]:
        return await profile_behavior(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_vulnerabilities(
            _to_dict(state),
            toolkit,
        )

    async def _segment(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_segmentation(
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

    graph = StateGraph(IoTOTSecurityState)
    graph.add_node("discover_devices", _discover)
    graph.add_node("profile_behavior", _profile)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node(
        "assess_vulnerabilities",
        _assess,
    )
    graph.add_node(
        "enforce_segmentation",
        _segment,
    )
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_devices")
    graph.add_edge(
        "discover_devices",
        "profile_behavior",
    )
    graph.add_edge(
        "profile_behavior",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "assess_vulnerabilities",
    )
    graph.add_conditional_edges(
        "assess_vulnerabilities",
        _needs_segmentation,
        {
            "enforce_segmentation": ("enforce_segmentation"),
            "report": "generate_report",
        },
    )
    graph.add_edge(
        "enforce_segmentation",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_iot_ot_security_graph(
    network_scanner: Any | None = None,
    ot_connector: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the IoT/OT Security graph with deps."""
    toolkit = IoTOTSecurityToolkit(
        network_scanner=network_scanner,
        ot_connector=ot_connector,
    )
    return build_graph(toolkit)
