"""LangGraph workflow for the Threat Intelligence Platform."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.threat_intelligence_platform.models import (
    ThreatIntelligencePlatformState,
)
from shieldops.agents.threat_intelligence_platform.nodes import (
    assess_relevance,
    collect_intelligence,
    correlate_threats,
    generate_advisories,
    normalize_indicators,
    report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "threat_intelligence_platform"


def should_generate_advisories(
    state: ThreatIntelligencePlatformState,
) -> str:
    """Route: generate advisories or skip to report.

    Skips advisory generation if no actionable intel
    was found or if an error occurred.
    """
    if state.error:
        return END
    if state.actionable_intel_count > 0:
        return "generate_advisories"
    if any(a.actionable for a in state.assessments):
        return "generate_advisories"
    return "report"


def create_threat_intelligence_platform_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the TIP LangGraph workflow.

    Workflow:
        collect_intelligence
        -> normalize_indicators
        -> correlate_threats
        -> assess_relevance
        -> [conditional: generate_advisories OR report]
        -> report
        -> END
    """
    graph = StateGraph(ThreatIntelligencePlatformState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "collect_intelligence",
        traced_node(
            f"{_AGENT}.collect_intelligence",
            _AGENT,
        )(collect_intelligence),
    )
    graph.add_node(
        "normalize_indicators",
        traced_node(
            f"{_AGENT}.normalize_indicators",
            _AGENT,
        )(normalize_indicators),
    )
    graph.add_node(
        "correlate_threats",
        traced_node(
            f"{_AGENT}.correlate_threats",
            _AGENT,
        )(correlate_threats),
    )
    graph.add_node(
        "assess_relevance",
        traced_node(
            f"{_AGENT}.assess_relevance",
            _AGENT,
        )(assess_relevance),
    )
    graph.add_node(
        "generate_advisories",
        traced_node(
            f"{_AGENT}.generate_advisories",
            _AGENT,
        )(generate_advisories),
    )
    graph.add_node(
        "report",
        traced_node(
            f"{_AGENT}.report",
            _AGENT,
        )(report),
    )

    # Define edges
    graph.set_entry_point("collect_intelligence")
    graph.add_edge(
        "collect_intelligence",
        "normalize_indicators",
    )
    graph.add_edge(
        "normalize_indicators",
        "correlate_threats",
    )
    graph.add_edge(
        "correlate_threats",
        "assess_relevance",
    )
    graph.add_conditional_edges(
        "assess_relevance",
        should_generate_advisories,
        {
            "generate_advisories": ("generate_advisories"),
            "report": "report",
            END: END,
        },
    )
    graph.add_edge("generate_advisories", "report")
    graph.add_edge("report", END)

    return graph
