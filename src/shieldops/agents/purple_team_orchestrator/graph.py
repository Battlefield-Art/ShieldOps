"""LangGraph workflow for Purple Team Orchestrator."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.purple_team_orchestrator.models import (
    PurpleTeamOrchestratorState,
)
from shieldops.agents.purple_team_orchestrator.nodes import (
    assess_responses,
    execute_attacks,
    monitor_detections,
    plan_exercise,
    report,
    score_exercise,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Purple Team Orchestrator workflow.

    Workflow::

        plan_exercise -> execute_attacks
            -> monitor_detections -> assess_responses
            -> score_exercise -> report -> END
    """
    _a = "purple_team_orchestrator"
    graph = StateGraph(PurpleTeamOrchestratorState)

    graph.add_node(
        "plan_exercise",
        traced_node(f"{_a}.plan_exercise", _a)(plan_exercise),
    )
    graph.add_node(
        "execute_attacks",
        traced_node(f"{_a}.execute_attacks", _a)(execute_attacks),
    )
    graph.add_node(
        "monitor_detections",
        traced_node(f"{_a}.monitor_detections", _a)(monitor_detections),
    )
    graph.add_node(
        "assess_responses",
        traced_node(f"{_a}.assess_responses", _a)(assess_responses),
    )
    graph.add_node(
        "score_exercise",
        traced_node(f"{_a}.score_exercise", _a)(score_exercise),
    )
    graph.add_node(
        "report",
        traced_node(f"{_a}.report", _a)(report),
    )

    graph.set_entry_point("plan_exercise")
    graph.add_edge("plan_exercise", "execute_attacks")
    graph.add_edge("execute_attacks", "monitor_detections")
    graph.add_edge("monitor_detections", "assess_responses")
    graph.add_edge("assess_responses", "score_exercise")
    graph.add_edge("score_exercise", "report")
    graph.add_edge("report", END)

    return graph


def create_purple_team_orchestrator_graph() -> StateGraph:
    """Factory to create the Purple Team graph."""
    return build_graph()
