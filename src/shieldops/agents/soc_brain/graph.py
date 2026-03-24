"""LangGraph workflow definition for the SOC Brain Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.soc_brain.models import SOCBrainState
from shieldops.agents.soc_brain.nodes import (
    analyze_situations,
    correlate_findings,
    create_situations,
    execute_response,
    ingest_telemetry,
    normalize_events,
    recommend_actions,
    triage_events,
    update_metrics,
)
from shieldops.agents.tracing import traced_node


def has_situation(state: SOCBrainState) -> str:
    """Route based on whether triage found a situation."""
    if state.enrichment_data.get("has_situation", False):
        return "create_situations"
    return "update_metrics"


def should_auto_execute(state: SOCBrainState) -> str:
    """Route based on whether there are auto-approved actions."""
    auto_actions = [a for a in state.recommended_actions if a.auto_approved]
    if auto_actions:
        return "execute_response"
    return "update_metrics"


def create_soc_brain_graph() -> StateGraph[SOCBrainState]:
    """Build the SOC Brain Agent LangGraph workflow.

    Workflow:
        ingest_telemetry → normalize_events → correlate_findings → triage_events
            → [situation found?]
                yes → create_situations → analyze_situations → recommend_actions
                    → [auto-approve?]
                        yes → execute_response → update_metrics → END
                        no  → update_metrics → END
                no  → update_metrics → END
    """
    graph = StateGraph(SOCBrainState)

    _agent = "soc_brain"
    graph.add_node(
        "ingest_telemetry",
        traced_node("soc_brain.ingest_telemetry", _agent)(ingest_telemetry),
    )
    graph.add_node(
        "normalize_events",
        traced_node("soc_brain.normalize_events", _agent)(normalize_events),
    )
    graph.add_node(
        "correlate_findings",
        traced_node("soc_brain.correlate_findings", _agent)(correlate_findings),
    )
    graph.add_node(
        "triage_events",
        traced_node("soc_brain.triage_events", _agent)(triage_events),
    )
    graph.add_node(
        "create_situations",
        traced_node("soc_brain.create_situations", _agent)(create_situations),
    )
    graph.add_node(
        "analyze_situations",
        traced_node("soc_brain.analyze_situations", _agent)(analyze_situations),
    )
    graph.add_node(
        "recommend_actions",
        traced_node("soc_brain.recommend_actions", _agent)(recommend_actions),
    )
    graph.add_node(
        "execute_response",
        traced_node("soc_brain.execute_response", _agent)(execute_response),
    )
    graph.add_node(
        "update_metrics",
        traced_node("soc_brain.update_metrics", _agent)(update_metrics),
    )

    # Define edges
    graph.set_entry_point("ingest_telemetry")
    graph.add_edge("ingest_telemetry", "normalize_events")
    graph.add_edge("normalize_events", "correlate_findings")
    graph.add_edge("correlate_findings", "triage_events")
    graph.add_conditional_edges(
        "triage_events",
        has_situation,
        {"create_situations": "create_situations", "update_metrics": "update_metrics"},
    )
    graph.add_edge("create_situations", "analyze_situations")
    graph.add_edge("analyze_situations", "recommend_actions")
    graph.add_conditional_edges(
        "recommend_actions",
        should_auto_execute,
        {"execute_response": "execute_response", "update_metrics": "update_metrics"},
    )
    graph.add_edge("execute_response", "update_metrics")
    graph.add_edge("update_metrics", END)

    return graph
