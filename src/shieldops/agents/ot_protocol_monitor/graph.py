"""OT Protocol Monitor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTProtocolMonitorState
from .nodes import (
    classify_threats,
    detect_anomalies,
    discover_devices,
    generate_alerts,
    generate_report,
    monitor_protocols,
)
from .tools import OTProtocolMonitorToolkit


def build_graph(toolkit: OTProtocolMonitorToolkit):  # type: ignore[no-untyped-def]
    """Build the ot_protocol_monitor agent graph (linear sequence)."""
    return build_linear_graph(
        OTProtocolMonitorState,
        [
            ("discover_devices", discover_devices),
            ("monitor_protocols", monitor_protocols),
            ("detect_anomalies", detect_anomalies),
            ("classify_threats", classify_threats),
            ("alert", generate_alerts),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_ot_protocol_monitor_graph(
    ot_connector: Any | None = None,
    threat_intel_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the OT Protocol Monitor graph."""
    toolkit = OTProtocolMonitorToolkit(
        ot_connector=ot_connector,
        threat_intel_api=threat_intel_api,
    )
    return build_graph(toolkit)
