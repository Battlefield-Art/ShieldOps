"""LangGraph workflow definition for the Cloud Resource
Tagger Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_resource_tagger.models import (
    CloudResourceTaggerState,
)
from shieldops.agents.cloud_resource_tagger.nodes import (
    analyze_metadata,
    apply_tags,
    generate_report,
    generate_tags,
    scan_resources,
    validate_compliance,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_resource_tagger"


def _should_apply(
    state: CloudResourceTaggerState,
) -> str:
    """Route after compliance: apply tags if
    recommendations exist, otherwise report."""
    if state.error:
        return "generate_report"
    if len(state.tag_recommendations) > 0:
        return "apply_tags"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Resource Tagger workflow.

    Workflow:
        scan_resources -> analyze_metadata -> generate_tags
            -> validate_compliance -> [tags? -> apply_tags]
            -> generate_report -> END
    """
    graph = StateGraph(CloudResourceTaggerState)

    graph.add_node(
        "scan_resources",
        traced_node(f"{_AGENT}.scan_resources", _AGENT)(scan_resources),
    )
    graph.add_node(
        "analyze_metadata",
        traced_node(f"{_AGENT}.analyze_metadata", _AGENT)(analyze_metadata),
    )
    graph.add_node(
        "generate_tags",
        traced_node(f"{_AGENT}.generate_tags", _AGENT)(generate_tags),
    )
    graph.add_node(
        "validate_compliance",
        traced_node(f"{_AGENT}.validate_compliance", _AGENT)(validate_compliance),
    )
    graph.add_node(
        "apply_tags",
        traced_node(f"{_AGENT}.apply_tags", _AGENT)(apply_tags),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("scan_resources")
    graph.add_edge("scan_resources", "analyze_metadata")
    graph.add_edge("analyze_metadata", "generate_tags")
    graph.add_edge("generate_tags", "validate_compliance")
    graph.add_conditional_edges(
        "validate_compliance",
        _should_apply,
        {
            "apply_tags": "apply_tags",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("apply_tags", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cloud_resource_tagger_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Cloud Resource Tagger graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
