"""LangGraph workflow definition for the Supply Chain
Risk Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.supply_chain_risk_monitor.models import (
    SupplyChainRiskMonitorState,
)
from shieldops.agents.supply_chain_risk_monitor.nodes import (
    analyze_dependencies,
    assess_impact,
    detect_risks,
    generate_report,
    mitigate,
    scan_supply_chain,
)
from shieldops.agents.tracing import traced_node

_AGENT = "supply_chain_risk_monitor"


def _should_mitigate(
    state: SupplyChainRiskMonitorState,
) -> str:
    """Route after impact assessment: mitigate if risks
    exist or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.risks_detected > 0:
        return "mitigate"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Supply Chain Risk Monitor LangGraph
    workflow.

    Workflow:
        scan_supply_chain -> analyze_dependencies
            -> detect_risks -> assess_impact
            -> [risks? -> mitigate]
            -> generate_report -> END
    """
    graph = StateGraph(SupplyChainRiskMonitorState)

    graph.add_node(
        "scan_supply_chain",
        traced_node(f"{_AGENT}.scan_supply_chain", _AGENT)(scan_supply_chain),
    )
    graph.add_node(
        "analyze_dependencies",
        traced_node(f"{_AGENT}.analyze_dependencies", _AGENT)(analyze_dependencies),
    )
    graph.add_node(
        "detect_risks",
        traced_node(f"{_AGENT}.detect_risks", _AGENT)(detect_risks),
    )
    graph.add_node(
        "assess_impact",
        traced_node(f"{_AGENT}.assess_impact", _AGENT)(assess_impact),
    )
    graph.add_node(
        "mitigate",
        traced_node(f"{_AGENT}.mitigate", _AGENT)(mitigate),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_supply_chain")
    graph.add_edge("scan_supply_chain", "analyze_dependencies")
    graph.add_edge("analyze_dependencies", "detect_risks")
    graph.add_edge("detect_risks", "assess_impact")
    graph.add_conditional_edges(
        "assess_impact",
        _should_mitigate,
        {
            "mitigate": "mitigate",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("mitigate", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_supply_chain_risk_monitor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Supply Chain Risk Monitor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
