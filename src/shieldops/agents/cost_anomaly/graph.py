"""LangGraph workflow definition for the Cost Anomaly Detector Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cost_anomaly.models import CostAnomalyState
from shieldops.agents.cost_anomaly.nodes import (
    analyze_llm_costs,
    classify_waste,
    collect_billing,
    detect_anomalies,
    generate_report,
    recommend,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cost_anomaly"


def create_cost_anomaly_graph() -> StateGraph[CostAnomalyState]:
    """Build the Cost Anomaly Detector LangGraph workflow.

    Workflow:
        collect_billing -> detect_anomalies -> classify_waste
            -> analyze_llm_costs -> recommend -> generate_report
    """
    graph = StateGraph(CostAnomalyState)

    graph.add_node(
        "collect_billing",
        traced_node("cost_anomaly.collect_billing", _AGENT)(collect_billing),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("cost_anomaly.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "classify_waste",
        traced_node("cost_anomaly.classify_waste", _AGENT)(classify_waste),
    )
    graph.add_node(
        "analyze_llm_costs",
        traced_node("cost_anomaly.analyze_llm_costs", _AGENT)(analyze_llm_costs),
    )
    graph.add_node(
        "recommend",
        traced_node("cost_anomaly.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "generate_report",
        traced_node("cost_anomaly.generate_report", _AGENT)(generate_report),
    )

    # Linear pipeline: collect -> detect -> classify -> llm_costs -> recommend -> report
    graph.set_entry_point("collect_billing")
    graph.add_edge("collect_billing", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_waste")
    graph.add_edge("classify_waste", "analyze_llm_costs")
    graph.add_edge("analyze_llm_costs", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
