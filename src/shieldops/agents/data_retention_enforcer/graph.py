"""Data Retention Enforcer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DataRetentionEnforcerState
from .nodes import (
    check_expiry,
    classify_retention,
    discover_data,
    enforce_deletion,
    report,
    verify_compliance,
)
from .tools import DataRetentionEnforcerToolkit


def build_graph(toolkit: DataRetentionEnforcerToolkit):  # type: ignore[no-untyped-def]
    """Build the data_retention_enforcer agent graph (linear sequence)."""
    return build_linear_graph(
        DataRetentionEnforcerState,
        [
            ("discover_data", discover_data),
            ("classify_retention", classify_retention),
            ("check_expiry", check_expiry),
            ("enforce_deletion", enforce_deletion),
            ("verify_compliance", verify_compliance),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_data_retention_enforcer_graph(
    data_catalog: Any | None = None,
    deletion_api: Any | None = None,
    legal_hold_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Retention Enforcer graph."""
    toolkit = DataRetentionEnforcerToolkit(
        data_catalog=data_catalog,
        deletion_api=deletion_api,
        legal_hold_api=legal_hold_api,
    )
    return build_graph(toolkit)
