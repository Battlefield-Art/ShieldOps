"""OT Protocol Monitor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: OTProtocolMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the OT Protocol Monitor graph.

    Flow:
        discover_devices -> monitor_protocols
        -> detect_anomalies -> classify_threats
        -> alert -> report
    """

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

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_protocols(
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

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_threats(
            _to_dict(state),
            toolkit,
        )

    async def _alert(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_alerts(
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

    graph = StateGraph(OTProtocolMonitorState)
    graph.add_node("discover_devices", _discover)
    graph.add_node("monitor_protocols", _monitor)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("classify_threats", _classify)
    graph.add_node("alert", _alert)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_devices")
    graph.add_edge(
        "discover_devices",
        "monitor_protocols",
    )
    graph.add_edge(
        "monitor_protocols",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "classify_threats",
    )
    graph.add_edge(
        "classify_threats",
        "alert",
    )
    graph.add_edge(
        "alert",
        "report",
    )
    graph.add_edge("report", END)

    return graph


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
