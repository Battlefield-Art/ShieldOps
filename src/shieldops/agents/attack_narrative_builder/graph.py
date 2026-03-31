"""Attack Narrative Builder Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AttackNarrativeBuilderState
from .nodes import (
    build_narrative,
    collect_events,
    correlate_timeline,
    generate_report,
    map_techniques,
    reconstruct_chain,
)
from .tools import AttackNarrativeBuilderToolkit


def build_graph(
    toolkit: AttackNarrativeBuilderToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Attack Narrative Builder graph.

    Flow:
        collect_events -> correlate_timeline
        -> reconstruct_chain -> map_techniques
        -> build_narrative -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_events(
            _to_dict(state),
            toolkit,
        )

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_timeline(
            _to_dict(state),
            toolkit,
        )

    async def _reconstruct(
        state: Any,
    ) -> dict[str, Any]:
        return await reconstruct_chain(
            _to_dict(state),
            toolkit,
        )

    async def _map(
        state: Any,
    ) -> dict[str, Any]:
        return await map_techniques(
            _to_dict(state),
            toolkit,
        )

    async def _narrative(
        state: Any,
    ) -> dict[str, Any]:
        return await build_narrative(
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

    graph = StateGraph(AttackNarrativeBuilderState)
    graph.add_node("collect_events", _collect)
    graph.add_node("correlate_timeline", _correlate)
    graph.add_node("reconstruct_chain", _reconstruct)
    graph.add_node("map_techniques", _map)
    graph.add_node("build_narrative", _narrative)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_events")
    graph.add_edge(
        "collect_events",
        "correlate_timeline",
    )
    graph.add_edge(
        "correlate_timeline",
        "reconstruct_chain",
    )
    graph.add_edge(
        "reconstruct_chain",
        "map_techniques",
    )
    graph.add_edge(
        "map_techniques",
        "build_narrative",
    )
    graph.add_edge(
        "build_narrative",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_attack_narrative_builder_graph(
    siem_source: Any | None = None,
    mitre_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Attack Narrative Builder graph."""
    toolkit = AttackNarrativeBuilderToolkit(
        siem_source=siem_source,
        mitre_api=mitre_api,
    )
    return build_graph(toolkit)
