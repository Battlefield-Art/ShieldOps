"""Compliance Drift Monitor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceDriftMonitorState
from .nodes import (
    assess_impact,
    compare_baseline,
    detect_drift,
    generate_report,
    scan_controls,
    send_alerts,
)
from .tools import ComplianceDriftMonitorToolkit


def build_graph(
    toolkit: ComplianceDriftMonitorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Drift Monitor graph.

    Flow:
        scan_controls -> compare_baseline
        -> detect_drift -> assess_impact
        -> send_alerts -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_controls(
            _to_dict(state),
            toolkit,
        )

    async def _compare(
        state: Any,
    ) -> dict[str, Any]:
        return await compare_baseline(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_drift(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_impact(
            _to_dict(state),
            toolkit,
        )

    async def _alert(
        state: Any,
    ) -> dict[str, Any]:
        return await send_alerts(
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

    graph = StateGraph(ComplianceDriftMonitorState)
    graph.add_node("scan_controls", _scan)
    graph.add_node("compare_baseline", _compare)
    graph.add_node("detect_drift", _detect)
    graph.add_node("assess_impact", _assess)
    graph.add_node("send_alerts", _alert)
    graph.add_node("report", _report)

    graph.set_entry_point("scan_controls")
    graph.add_edge(
        "scan_controls",
        "compare_baseline",
    )
    graph.add_edge(
        "compare_baseline",
        "detect_drift",
    )
    graph.add_edge(
        "detect_drift",
        "assess_impact",
    )
    graph.add_edge(
        "assess_impact",
        "send_alerts",
    )
    graph.add_edge(
        "send_alerts",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_compliance_drift_monitor_graph(
    compliance_store: Any | None = None,
    alert_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Compliance Drift Monitor graph."""
    toolkit = ComplianceDriftMonitorToolkit(
        compliance_store=compliance_store,
        alert_service=alert_service,
    )
    return build_graph(toolkit)
