"""LangGraph workflow definition for the Threat Intel Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.threat_intel.models import ThreatIntelState
from shieldops.agents.threat_intel.nodes import (
    assess_threats,
    collect_indicators,
    correlate_observations,
    distribute_intel,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_distribute(state: ThreatIntelState) -> str:
    """Decide whether to distribute intel based on assessment results.

    Skips distribution if there are no actionable indicators or if an error
    occurred during assessment.
    """
    if state.error:
        return END
    if state.high_priority_count > 0:
        return "distribute_intel"
    # Still distribute if there are any actionable assessments
    if any(a.actionable for a in state.assessments):
        return "distribute_intel"
    return END


def create_threat_intel_graph() -> StateGraph:
    """Build the Threat Intel Agent LangGraph workflow.

    Workflow:
        collect_indicators -> correlate_observations -> assess_threats
            -> [conditional: distribute_intel OR end]
    """
    graph = StateGraph(ThreatIntelState)

    _agent = "threat_intel"

    # Add nodes (wrapped with OTEL tracing spans)
    graph.add_node(
        "collect_indicators",
        traced_node("threat_intel.collect_indicators", _agent)(collect_indicators),
    )
    graph.add_node(
        "correlate_observations",
        traced_node("threat_intel.correlate_observations", _agent)(correlate_observations),
    )
    graph.add_node(
        "assess_threats",
        traced_node("threat_intel.assess_threats", _agent)(assess_threats),
    )
    graph.add_node(
        "distribute_intel",
        traced_node("threat_intel.distribute_intel", _agent)(distribute_intel),
    )

    # Define edges
    graph.set_entry_point("collect_indicators")
    graph.add_edge("collect_indicators", "correlate_observations")
    graph.add_edge("correlate_observations", "assess_threats")
    graph.add_conditional_edges(
        "assess_threats",
        should_distribute,
        {
            "distribute_intel": "distribute_intel",
            END: END,
        },
    )
    graph.add_edge("distribute_intel", END)

    return graph
