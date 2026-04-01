"""LangGraph workflow for the Threat Actor Profiler Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_actor_profiler.models import (
    ThreatActorProfilerState,
)
from shieldops.agents.threat_actor_profiler.nodes import (
    assess_targeting,
    build_profiles,
    cluster_activity,
    collect_indicators,
    generate_report,
    map_ttps,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_actor_profiler"


def _should_build_profiles(
    state: ThreatActorProfilerState,
) -> str:
    """Route after clustering."""
    if state.error:
        return "generate_report"
    if state.clusters:
        return "build_profiles"
    return "generate_report"


def _should_assess(
    state: ThreatActorProfilerState,
) -> str:
    """Route after TTP mapping."""
    if state.ttp_mappings:
        return "assess_targeting"
    return "generate_report"


def create_threat_actor_profiler_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Actor Profiler LangGraph.

    Workflow:
        collect_indicators -> cluster_activity
          -> [has_clusters?] -> build_profiles -> map_ttps
          -> [has_mappings?] -> assess_targeting
          -> generate_report
    """
    graph = StateGraph(ThreatActorProfilerState)

    graph.add_node(
        "collect_indicators",
        traced_node(f"{_AGENT}.collect_indicators", _AGENT)(collect_indicators),
    )
    graph.add_node(
        "cluster_activity",
        traced_node(f"{_AGENT}.cluster_activity", _AGENT)(cluster_activity),
    )
    graph.add_node(
        "build_profiles",
        traced_node(f"{_AGENT}.build_profiles", _AGENT)(build_profiles),
    )
    graph.add_node(
        "map_ttps",
        traced_node(f"{_AGENT}.map_ttps", _AGENT)(map_ttps),
    )
    graph.add_node(
        "assess_targeting",
        traced_node(f"{_AGENT}.assess_targeting", _AGENT)(assess_targeting),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_indicators")
    graph.add_edge("collect_indicators", "cluster_activity")
    graph.add_conditional_edges(
        "cluster_activity",
        _should_build_profiles,
        {
            "build_profiles": "build_profiles",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("build_profiles", "map_ttps")
    graph.add_conditional_edges(
        "map_ttps",
        _should_assess,
        {
            "assess_targeting": "assess_targeting",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_targeting", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
