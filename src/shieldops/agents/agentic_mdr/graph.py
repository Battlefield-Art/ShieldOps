"""LangGraph workflow definition for the Agentic MDR Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.agentic_mdr.models import (
    AgenticMDRState,
    ResponseDecision,
)
from shieldops.agents.agentic_mdr.nodes import (
    auto_triage,
    decide_response,
    execute_response,
    ingest_alerts,
    investigate,
    report,
    validate_and_learn,
)
from shieldops.agents.tracing import traced_node

_AGENT = "agentic_mdr"


# ------------------------------------------------------------------
# Routing functions
# ------------------------------------------------------------------


def _has_actionable_alerts(
    state: AgenticMDRState,
) -> str:
    """Route after triage: investigate or skip to report."""
    active = [t for t in state.triage_results if not t.suppressed]
    if active:
        return "investigate"
    return "report"


def _needs_execution(
    state: AgenticMDRState,
) -> str:
    """Route after decide: execute or validate."""
    auto = [a for a in state.response_actions if a.decision == ResponseDecision.AUTO_REMEDIATE]
    if auto:
        return "execute_response"
    return "validate_and_learn"


# ------------------------------------------------------------------
# Graph builder
# ------------------------------------------------------------------


def build_graph() -> StateGraph:
    """Build the Agentic MDR StateGraph.

    Workflow:
        ingest_alerts -> auto_triage
            -> [actionable?]
                yes -> investigate -> decide_response
                    -> [auto-remediate?]
                        yes -> execute_response
                              -> validate_and_learn -> report -> END
                        no  -> validate_and_learn -> report -> END
                no  -> report -> END
    """
    graph = StateGraph(AgenticMDRState)

    graph.add_node(
        "ingest_alerts",
        traced_node(f"{_AGENT}.ingest_alerts", _AGENT)(ingest_alerts),
    )
    graph.add_node(
        "auto_triage",
        traced_node(f"{_AGENT}.auto_triage", _AGENT)(auto_triage),
    )
    graph.add_node(
        "investigate",
        traced_node(f"{_AGENT}.investigate", _AGENT)(investigate),
    )
    graph.add_node(
        "decide_response",
        traced_node(f"{_AGENT}.decide_response", _AGENT)(decide_response),
    )
    graph.add_node(
        "execute_response",
        traced_node(f"{_AGENT}.execute_response", _AGENT)(execute_response),
    )
    graph.add_node(
        "validate_and_learn",
        traced_node(f"{_AGENT}.validate_and_learn", _AGENT)(validate_and_learn),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    # Edges
    graph.set_entry_point("ingest_alerts")
    graph.add_edge("ingest_alerts", "auto_triage")
    graph.add_conditional_edges(
        "auto_triage",
        _has_actionable_alerts,
        {
            "investigate": "investigate",
            "report": "report",
        },
    )
    graph.add_edge("investigate", "decide_response")
    graph.add_conditional_edges(
        "decide_response",
        _needs_execution,
        {
            "execute_response": "execute_response",
            "validate_and_learn": "validate_and_learn",
        },
    )
    graph.add_edge("execute_response", "validate_and_learn")
    graph.add_edge("validate_and_learn", "report")
    graph.add_edge("report", END)

    return graph


def create_agentic_mdr_graph() -> StateGraph:
    """Factory function following ShieldOps convention."""
    return build_graph()
