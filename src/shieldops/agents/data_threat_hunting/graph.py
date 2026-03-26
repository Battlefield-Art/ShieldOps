"""LangGraph workflow definition for the Data Threat Hunting Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.data_threat_hunting.models import (
    DataThreatHuntingState,
)
from shieldops.agents.data_threat_hunting.nodes import (
    analyze_indicators,
    collect_evidence,
    correlate_findings,
    generate_hypotheses,
    hunt_in_backups,
    report,
)
from shieldops.agents.tracing import traced_node


def should_hunt_backups(
    state: DataThreatHuntingState,
) -> str:
    """Route to backup hunting if backup sources are targeted."""
    if state.error:
        return "report"

    sources = state.target_sources or []
    has_backup = "backup_snapshot" in sources
    has_indicators = len(state.indicators) > 0
    scope_has_snapshots = bool(state.hunt_scope.get("snapshot_ids"))

    if has_backup or scope_has_snapshots or has_indicators:
        return "hunt_in_backups"
    return "correlate_findings"


def create_data_threat_hunting_graph() -> StateGraph[DataThreatHuntingState]:
    """Build the Data Threat Hunting Agent LangGraph workflow.

    Workflow:
        generate_hypotheses -> collect_evidence
            -> analyze_indicators
            -> [backup_sources? -> hunt_in_backups]
            -> correlate_findings -> report -> END
    """
    graph = StateGraph(DataThreatHuntingState)

    _agent = "data_threat_hunting"
    graph.add_node(
        "generate_hypotheses",
        traced_node(
            "data_threat_hunting.generate_hypotheses",
            _agent,
        )(generate_hypotheses),
    )
    graph.add_node(
        "collect_evidence",
        traced_node(
            "data_threat_hunting.collect_evidence",
            _agent,
        )(collect_evidence),
    )
    graph.add_node(
        "analyze_indicators",
        traced_node(
            "data_threat_hunting.analyze_indicators",
            _agent,
        )(analyze_indicators),
    )
    graph.add_node(
        "hunt_in_backups",
        traced_node(
            "data_threat_hunting.hunt_in_backups",
            _agent,
        )(hunt_in_backups),
    )
    graph.add_node(
        "correlate_findings",
        traced_node(
            "data_threat_hunting.correlate_findings",
            _agent,
        )(correlate_findings),
    )
    graph.add_node(
        "report",
        traced_node(
            "data_threat_hunting.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("generate_hypotheses")
    graph.add_edge("generate_hypotheses", "collect_evidence")
    graph.add_edge("collect_evidence", "analyze_indicators")
    graph.add_conditional_edges(
        "analyze_indicators",
        should_hunt_backups,
        {
            "hunt_in_backups": "hunt_in_backups",
            "correlate_findings": "correlate_findings",
            "report": "report",
        },
    )
    graph.add_edge("hunt_in_backups", "correlate_findings")
    graph.add_edge("correlate_findings", "report")
    graph.add_edge("report", END)

    return graph
