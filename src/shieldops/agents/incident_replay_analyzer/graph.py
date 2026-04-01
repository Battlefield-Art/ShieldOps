"""LangGraph workflow for the Incident Replay Analyzer."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_replay_analyzer.models import (
    IncidentReplayAnalyzerState,
)
from shieldops.agents.incident_replay_analyzer.nodes import (
    analyze_decisions,
    generate_playbooks,
    generate_report,
    identify_improvements,
    reconstruct_timeline,
    select_incidents,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_replay_analyzer"


def _should_analyze(
    state: IncidentReplayAnalyzerState,
) -> str:
    if state.error:
        return "generate_report"
    if state.timeline_events:
        return "analyze_decisions"
    return "generate_report"


def _should_generate_playbooks(
    state: IncidentReplayAnalyzerState,
) -> str:
    if state.improvements:
        return "generate_playbooks"
    return "generate_report"


def create_incident_replay_analyzer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Replay Analyzer LangGraph.

    Workflow:
        select_incidents -> reconstruct_timeline
          -> [has_events?] -> analyze_decisions
          -> identify_improvements
          -> [has_improvements?] -> generate_playbooks
          -> generate_report
    """
    graph = StateGraph(IncidentReplayAnalyzerState)

    graph.add_node(
        "select_incidents",
        traced_node(f"{_AGENT}.select_incidents", _AGENT)(
            select_incidents,
        ),
    )
    graph.add_node(
        "reconstruct_timeline",
        traced_node(
            f"{_AGENT}.reconstruct_timeline",
            _AGENT,
        )(reconstruct_timeline),
    )
    graph.add_node(
        "analyze_decisions",
        traced_node(f"{_AGENT}.analyze_decisions", _AGENT)(
            analyze_decisions,
        ),
    )
    graph.add_node(
        "identify_improvements",
        traced_node(
            f"{_AGENT}.identify_improvements",
            _AGENT,
        )(identify_improvements),
    )
    graph.add_node(
        "generate_playbooks",
        traced_node(f"{_AGENT}.generate_playbooks", _AGENT)(
            generate_playbooks,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("select_incidents")
    graph.add_edge("select_incidents", "reconstruct_timeline")
    graph.add_conditional_edges(
        "reconstruct_timeline",
        _should_analyze,
        {
            "analyze_decisions": "analyze_decisions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_decisions", "identify_improvements")
    graph.add_conditional_edges(
        "identify_improvements",
        _should_generate_playbooks,
        {
            "generate_playbooks": "generate_playbooks",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_playbooks", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
