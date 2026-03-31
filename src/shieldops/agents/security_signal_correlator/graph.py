"""Security Signal Correlator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecuritySignalCorrelatorState
from .nodes import (
    collect_signals,
    correlate,
    generate_incidents,
    generate_report,
    normalize,
    score_confidence,
)
from .tools import SecuritySignalCorrelatorToolkit


def build_graph(
    toolkit: SecuritySignalCorrelatorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Signal Correlator graph.

    Flow:
        collect_signals -> normalize -> correlate
        -> score_confidence -> generate_incidents -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_signals(
            _to_dict(state),
            toolkit,
        )

    async def _normalize(
        state: Any,
    ) -> dict[str, Any]:
        return await normalize(
            _to_dict(state),
            toolkit,
        )

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate(
            _to_dict(state),
            toolkit,
        )

    async def _score(
        state: Any,
    ) -> dict[str, Any]:
        return await score_confidence(
            _to_dict(state),
            toolkit,
        )

    async def _incidents(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_incidents(
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

    graph = StateGraph(SecuritySignalCorrelatorState)
    graph.add_node("collect_signals", _collect)
    graph.add_node("normalize", _normalize)
    graph.add_node("correlate", _correlate)
    graph.add_node("score_confidence", _score)
    graph.add_node("generate_incidents", _incidents)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_signals")
    graph.add_edge(
        "collect_signals",
        "normalize",
    )
    graph.add_edge(
        "normalize",
        "correlate",
    )
    graph.add_edge(
        "correlate",
        "score_confidence",
    )
    graph.add_edge(
        "score_confidence",
        "generate_incidents",
    )
    graph.add_edge(
        "generate_incidents",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_signal_correlator_graph(
    signal_sources: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Signal Correlator graph."""
    toolkit = SecuritySignalCorrelatorToolkit(
        signal_sources=signal_sources,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
