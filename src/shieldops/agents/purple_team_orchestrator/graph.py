"""LangGraph workflow for Purple Team Orchestrator."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import PurpleTeamOrchestratorState
from .nodes import (
    assess_responses,
    execute_attacks,
    monitor_detections,
    plan_exercise,
    report,
    score_exercise,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the purple_team_orchestrator agent graph (linear sequence)."""
    return build_linear_graph(
        PurpleTeamOrchestratorState,
        [
            ("plan_exercise", plan_exercise),
            ("execute_attacks", execute_attacks),
            ("monitor_detections", monitor_detections),
            ("assess_responses", assess_responses),
            ("score_exercise", score_exercise),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_purple_team_orchestrator_graph() -> StateGraph:
    """Factory to create the Purple Team graph."""
    return build_graph()
