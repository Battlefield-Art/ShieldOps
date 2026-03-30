"""Network Traffic Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import NetworkTrafficAnalyzerState
from .nodes import (
    analyze_patterns,
    capture_flows,
    classify_threats,
    detect_anomalies,
    enforce_policies,
    generate_report,
)
from .tools import NetworkTrafficAnalyzerToolkit


def _has_anomalies(state: Any) -> str:
    """Route: enforce policies only if threats exist."""
    threats = state.threats if hasattr(state, "threats") else state.get("threats", [])
    if threats:
        return "enforce_policies"
    return "report"


def build_graph(
    toolkit: NetworkTrafficAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Network Traffic Analyzer graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _capture(
        state: Any,
    ) -> dict[str, Any]:
        return await capture_flows(
            _to_dict(state),
            toolkit,
        )

    async def _patterns(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _anomalies(
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

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_policies(
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

    graph = StateGraph(NetworkTrafficAnalyzerState)
    graph.add_node("capture_flows", _capture)
    graph.add_node("analyze_patterns", _patterns)
    graph.add_node("detect_anomalies", _anomalies)
    graph.add_node("classify_threats", _classify)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("capture_flows")
    graph.add_edge(
        "capture_flows",
        "analyze_patterns",
    )
    graph.add_edge(
        "analyze_patterns",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "classify_threats",
    )
    graph.add_conditional_edges(
        "classify_threats",
        _has_anomalies,
        {
            "enforce_policies": "enforce_policies",
            "report": "generate_report",
        },
    )
    graph.add_edge(
        "enforce_policies",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_network_traffic_analyzer_graph(
    flow_source: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Network Traffic Analyzer graph."""
    toolkit = NetworkTrafficAnalyzerToolkit(
        flow_source=flow_source,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
