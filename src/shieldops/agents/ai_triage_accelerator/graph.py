"""LangGraph workflow definition for the AI Triage Accelerator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ai_triage_accelerator.models import (
    AITriageAcceleratorState,
)
from shieldops.agents.ai_triage_accelerator.nodes import (
    batch_ingest,
    confidence_score,
    enrich_context,
    parallel_classify,
    report,
    route_decisions,
)
from shieldops.agents.tracing import traced_node

_AGENT = "ai_triage_accelerator"


def create_ai_triage_accelerator_graph() -> StateGraph:
    """Build the AI Triage Accelerator LangGraph workflow.

    Workflow:
        batch_ingest -> parallel_classify -> enrich_context
        -> confidence_score -> route_decisions -> report -> END
    """
    graph = StateGraph(AITriageAcceleratorState)

    graph.add_node(
        "batch_ingest",
        traced_node(
            "ai_triage_accelerator.batch_ingest",
            _AGENT,
        )(batch_ingest),
    )
    graph.add_node(
        "parallel_classify",
        traced_node(
            "ai_triage_accelerator.parallel_classify",
            _AGENT,
        )(parallel_classify),
    )
    graph.add_node(
        "enrich_context",
        traced_node(
            "ai_triage_accelerator.enrich_context",
            _AGENT,
        )(enrich_context),
    )
    graph.add_node(
        "confidence_score",
        traced_node(
            "ai_triage_accelerator.confidence_score",
            _AGENT,
        )(confidence_score),
    )
    graph.add_node(
        "route_decisions",
        traced_node(
            "ai_triage_accelerator.route_decisions",
            _AGENT,
        )(route_decisions),
    )
    graph.add_node(
        "report",
        traced_node(
            "ai_triage_accelerator.report",
            _AGENT,
        )(report),
    )

    # Linear pipeline
    graph.set_entry_point("batch_ingest")
    graph.add_edge("batch_ingest", "parallel_classify")
    graph.add_edge("parallel_classify", "enrich_context")
    graph.add_edge("enrich_context", "confidence_score")
    graph.add_edge("confidence_score", "route_decisions")
    graph.add_edge("route_decisions", "report")
    graph.add_edge("report", END)

    return graph
