"""API Token Rotator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import APITokenRotatorState
from .nodes import (
    assess_risk,
    audit_age,
    discover_tokens,
    generate_report,
    rotate_tokens,
)
from .tools import APITokenRotatorToolkit


def build_graph(toolkit: APITokenRotatorToolkit):  # type: ignore[no-untyped-def]
    """Build the api_token_rotator agent graph (linear sequence)."""
    return build_linear_graph(
        APITokenRotatorState,
        [
            ("discover_tokens", discover_tokens),
            ("audit_age", audit_age),
            ("assess_risk", assess_risk),
            ("rotate", rotate_tokens),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_api_token_rotator_graph(
    credential_store: Any | None = None,
    secret_manager: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the API Token Rotator graph."""
    toolkit = APITokenRotatorToolkit(
        credential_store=credential_store,
        secret_manager=secret_manager,
    )
    return build_graph(toolkit)
