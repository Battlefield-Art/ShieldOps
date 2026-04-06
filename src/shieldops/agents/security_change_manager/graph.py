"""Security Change Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityChangeManagerState
from .nodes import (
    approve_or_reject,
    assess_risk,
    check_dependencies,
    generate_report,
    monitor_rollout,
    receive_change,
)
from .tools import SecurityChangeManagerToolkit


def build_graph(toolkit: SecurityChangeManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the security_change_manager agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityChangeManagerState,
        [
            ("receive_change", receive_change),
            ("assess_risk", assess_risk),
            ("check_dependencies", check_dependencies),
            ("approve_or_reject", approve_or_reject),
            ("monitor_rollout", monitor_rollout),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_change_manager_graph(
    change_source: Any | None = None,
    approval_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Change Manager graph."""
    toolkit = SecurityChangeManagerToolkit(
        change_source=change_source,
        approval_api=approval_api,
    )
    return build_graph(toolkit)
