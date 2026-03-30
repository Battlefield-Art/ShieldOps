"""DNS Threat Analyzer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DNSThreatAnalyzerState
from .nodes import (
    analyze_patterns,
    classify_domains,
    collect_dns_logs,
    detect_threats,
    enforce_blocks,
    generate_report,
)
from .tools import DNSThreatAnalyzerToolkit


def build_graph(
    toolkit: DNSThreatAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the DNS Threat Analyzer graph.

    Flow:
        collect_dns_logs -> analyze_patterns
        -> detect_threats -> classify_domains
        -> enforce_blocks -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_dns_logs(
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
        return await detect_threats(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_domains(
            _to_dict(state),
            toolkit,
        )

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_blocks(
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

    graph = StateGraph(DNSThreatAnalyzerState)
    graph.add_node("collect_dns_logs", _collect)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("detect_threats", _detect)
    graph.add_node("classify_domains", _classify)
    graph.add_node("enforce_blocks", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_dns_logs")
    graph.add_edge(
        "collect_dns_logs",
        "analyze_patterns",
    )
    graph.add_edge(
        "analyze_patterns",
        "detect_threats",
    )
    graph.add_edge(
        "detect_threats",
        "classify_domains",
    )
    graph.add_edge(
        "classify_domains",
        "enforce_blocks",
    )
    graph.add_edge(
        "enforce_blocks",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_dns_threat_analyzer_graph(
    dns_log_source: Any | None = None,
    threat_intel_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Threat Analyzer graph."""
    toolkit = DNSThreatAnalyzerToolkit(
        dns_log_source=dns_log_source,
        threat_intel_api=threat_intel_api,
    )
    return build_graph(toolkit)
