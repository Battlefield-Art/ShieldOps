"""LangGraph workflow definition for the Attack Narrative Builder Agent."""

from __future__ import annotations

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.attack_narrative_builder.models import (
    AttackNarrativeBuilderState,
)
from shieldops.agents.attack_narrative_builder.nodes import (
    build_timeline,
    cluster_events,
    collect_events,
    generate_narrative,
    generate_report,
    map_mitre,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "attack_narrative_builder"


def _should_narrate(state: AttackNarrativeBuilderState) -> str:
    """Route after timeline: generate narrative if clusters exist,
    otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.clusters:
        return "generate_narrative"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Attack Narrative Builder LangGraph workflow.

    Workflow:
        collect_events -> cluster_events -> build_timeline
            -> [clusters? -> generate_narrative -> map_mitre]
            -> generate_report -> END
    """
    graph = StateGraph(AttackNarrativeBuilderState)

    graph.add_node(
        "collect_events",
        traced_node(f"{_AGENT}.collect_events", _AGENT)(collect_events),
    )
    graph.add_node(
        "cluster_events",
        traced_node(f"{_AGENT}.cluster_events", _AGENT)(cluster_events),
    )
    graph.add_node(
        "build_timeline",
        traced_node(f"{_AGENT}.build_timeline", _AGENT)(build_timeline),
    )
    graph.add_node(
        "generate_narrative",
        traced_node(f"{_AGENT}.generate_narrative", _AGENT)(generate_narrative),
    )
    graph.add_node(
        "map_mitre",
        traced_node(f"{_AGENT}.map_mitre", _AGENT)(map_mitre),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_events")
    graph.add_edge("collect_events", "cluster_events")
    graph.add_edge("cluster_events", "build_timeline")
    graph.add_conditional_edges(
        "build_timeline",
        _should_narrate,
        {
            "generate_narrative": "generate_narrative",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_narrative", "map_mitre")
    graph.add_edge("map_mitre", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_attack_narrative_builder_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Attack Narrative Builder graph
    with optional dependency injection."""
    if any(clients.values()):
        from shieldops.agents.attack_narrative_builder.nodes import (
            set_toolkit,
        )
        from shieldops.agents.attack_narrative_builder.tools import (
            AttackNarrativeBuilderToolkit,
        )

        toolkit = AttackNarrativeBuilderToolkit(
            siem_client=clients.get("siem_client"),
            mitre_client=clients.get("mitre_client"),
            repository=clients.get("repository"),
        )
        set_toolkit(toolkit)

    return build_graph(toolkit=clients.get("toolkit"))
