"""Risk Scoring Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from shieldops.agents.framework import build_linear_graph

from .models import RiskScoringState
from .nodes import (
    aggregate_by_entity,
    collect_observations,
    decide_actions,
    enrich_observations,
)
from .tools import RiskScoringToolkit


def build_graph(toolkit: RiskScoringToolkit):  # type: ignore[no-untyped-def]
    """Build the risk_scoring agent graph (linear sequence)."""
    return build_linear_graph(
        RiskScoringState,
        [
            ("collect", collect_observations),
            ("enrich", enrich_observations),
            ("aggregate", aggregate_by_entity),
            ("decide", decide_actions),
        ],
        toolkit=toolkit,
    )
