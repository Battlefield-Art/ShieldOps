"""LangGraph workflow for the Data Exfiltration Monitor Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.data_exfiltration_monitor.models import (
    DataExfiltrationMonitorState,
)
from shieldops.agents.data_exfiltration_monitor.nodes import (
    analyze_flows,
    block_transfers,
    classify_sensitivity,
    detect_exfiltration,
    generate_report,
    monitor_channels,
)
from shieldops.agents.tracing import traced_node

_AGENT = "data_exfiltration_monitor"


def _should_analyze(
    state: DataExfiltrationMonitorState,
) -> str:
    """Route after channel monitoring based on results."""
    if state.error:
        return "generate_report"
    if state.data_flows:
        return "analyze_flows"
    return "generate_report"


def _should_block(
    state: DataExfiltrationMonitorState,
) -> str:
    """Route after classification — block if sensitive."""
    if state.sensitive_count > 0:
        return "block_transfers"
    return "generate_report"


def create_data_exfiltration_monitor_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Exfiltration Monitor LangGraph.

    Workflow:
        monitor_channels
          -> [has_flows?] -> analyze_flows
          -> detect_exfiltration
          -> classify_sensitivity
          -> [sensitive?] -> block_transfers
          -> generate_report
    """
    graph = StateGraph(DataExfiltrationMonitorState)

    graph.add_node(
        "monitor_channels",
        traced_node(
            f"{_AGENT}.monitor_channels",
            _AGENT,
        )(monitor_channels),
    )
    graph.add_node(
        "analyze_flows",
        traced_node(
            f"{_AGENT}.analyze_flows",
            _AGENT,
        )(analyze_flows),
    )
    graph.add_node(
        "detect_exfiltration",
        traced_node(
            f"{_AGENT}.detect_exfiltration",
            _AGENT,
        )(detect_exfiltration),
    )
    graph.add_node(
        "classify_sensitivity",
        traced_node(
            f"{_AGENT}.classify_sensitivity",
            _AGENT,
        )(classify_sensitivity),
    )
    graph.add_node(
        "block_transfers",
        traced_node(
            f"{_AGENT}.block_transfers",
            _AGENT,
        )(block_transfers),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("monitor_channels")
    graph.add_conditional_edges(
        "monitor_channels",
        _should_analyze,
        {
            "analyze_flows": "analyze_flows",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_flows", "detect_exfiltration")
    graph.add_edge(
        "detect_exfiltration",
        "classify_sensitivity",
    )
    graph.add_conditional_edges(
        "classify_sensitivity",
        _should_block,
        {
            "block_transfers": "block_transfers",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("block_transfers", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
