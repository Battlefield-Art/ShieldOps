"""LangGraph workflow for the Mobile Threat Defender Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.mobile_threat_defender.models import (
    MobileThreatDefenderState,
)
from shieldops.agents.mobile_threat_defender.nodes import (
    analyze_apps,
    check_network,
    detect_threats,
    enforce_policy,
    generate_report,
    scan_device,
)
from shieldops.agents.tracing import traced_node

_AGENT = "mobile_threat_defender"


def _should_analyze(
    state: MobileThreatDefenderState,
) -> str:
    """Route after device scan based on results."""
    if state.error:
        return "generate_report"
    if state.device_scans:
        return "analyze_apps"
    return "generate_report"


def _should_enforce(
    state: MobileThreatDefenderState,
) -> str:
    """Route after threat detection."""
    if state.detected_threats:
        return "enforce_policy"
    return "generate_report"


def create_mobile_threat_defender_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Mobile Threat Defender LangGraph.

    Workflow:
        scan_device
          -> [has_devices?] -> analyze_apps
          -> check_network
          -> detect_threats
          -> [has_threats?] -> enforce_policy
          -> generate_report
    """
    graph = StateGraph(MobileThreatDefenderState)

    graph.add_node(
        "scan_device",
        traced_node(
            f"{_AGENT}.scan_device",
            _AGENT,
        )(scan_device),
    )
    graph.add_node(
        "analyze_apps",
        traced_node(
            f"{_AGENT}.analyze_apps",
            _AGENT,
        )(analyze_apps),
    )
    graph.add_node(
        "check_network",
        traced_node(
            f"{_AGENT}.check_network",
            _AGENT,
        )(check_network),
    )
    graph.add_node(
        "detect_threats",
        traced_node(
            f"{_AGENT}.detect_threats",
            _AGENT,
        )(detect_threats),
    )
    graph.add_node(
        "enforce_policy",
        traced_node(
            f"{_AGENT}.enforce_policy",
            _AGENT,
        )(enforce_policy),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_device")
    graph.add_conditional_edges(
        "scan_device",
        _should_analyze,
        {
            "analyze_apps": "analyze_apps",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_apps", "check_network")
    graph.add_edge("check_network", "detect_threats")
    graph.add_conditional_edges(
        "detect_threats",
        _should_enforce,
        {
            "enforce_policy": "enforce_policy",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policy", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
