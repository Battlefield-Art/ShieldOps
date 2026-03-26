"""LangGraph workflow definition for the Log Intelligence Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.log_intelligence.models import (
    LogIntelligenceState,
)
from shieldops.agents.log_intelligence.nodes import (
    correlate_threats,
    detect_patterns,
    generate_insights,
    generate_report,
    ingest_logs,
    parse_and_normalize,
)
from shieldops.agents.tracing import traced_node

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def should_correlate(
    state: LogIntelligenceState,
) -> str:
    """Route to threat correlation if patterns exist."""
    if state.error:
        return "generate_report"
    if state.patterns_detected:
        return "correlate_threats"
    return "generate_report"


def should_generate_insights(
    state: LogIntelligenceState,
) -> str:
    """Route to insight generation if threats or patterns exist."""
    if state.error:
        return "generate_report"
    if state.threats_correlated or state.patterns_detected:
        return "generate_insights"
    return "generate_report"


def create_log_intelligence_graph() -> StateGraph[LogIntelligenceState]:
    """Build the Log Intelligence Agent LangGraph workflow.

    Workflow:
        ingest_logs -> parse_and_normalize -> detect_patterns
            -> [patterns? -> correlate_threats]
            -> [threats/patterns? -> generate_insights]
            -> generate_report -> END
    """
    graph = StateGraph(LogIntelligenceState)

    _agent = "log_intelligence"
    graph.add_node(
        "ingest_logs",
        traced_node("log_intelligence.ingest_logs", _agent)(ingest_logs),
    )
    graph.add_node(
        "parse_and_normalize",
        traced_node(
            "log_intelligence.parse_and_normalize",
            _agent,
        )(parse_and_normalize),
    )
    graph.add_node(
        "detect_patterns",
        traced_node("log_intelligence.detect_patterns", _agent)(detect_patterns),
    )
    graph.add_node(
        "correlate_threats",
        traced_node(
            "log_intelligence.correlate_threats",
            _agent,
        )(correlate_threats),
    )
    graph.add_node(
        "generate_insights",
        traced_node(
            "log_intelligence.generate_insights",
            _agent,
        )(generate_insights),
    )
    graph.add_node(
        "generate_report",
        traced_node("log_intelligence.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("ingest_logs")
    graph.add_edge("ingest_logs", "parse_and_normalize")
    graph.add_edge("parse_and_normalize", "detect_patterns")
    graph.add_conditional_edges(
        "detect_patterns",
        should_correlate,
        {
            "correlate_threats": "correlate_threats",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "correlate_threats",
        should_generate_insights,
        {
            "generate_insights": "generate_insights",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_insights", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
