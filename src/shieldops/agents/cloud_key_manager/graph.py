"""Cloud Key Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CloudKeyManagerState
from .nodes import (
    assess_risk,
    audit_rotation,
    check_usage,
    discover_keys,
    enforce_policy,
    generate_report,
)
from .tools import CloudKeyManagerToolkit


def build_graph(toolkit: CloudKeyManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_key_manager agent graph (linear sequence)."""
    return build_linear_graph(
        CloudKeyManagerState,
        [
            ("discover_keys", discover_keys),
            ("audit_rotation", audit_rotation),
            ("check_usage", check_usage),
            ("assess_risk", assess_risk),
            ("enforce_policy", enforce_policy),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_cloud_key_manager_graph(
    kms_client: Any | None = None,
    vault_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Key Manager graph."""
    toolkit = CloudKeyManagerToolkit(
        kms_client=kms_client,
        vault_client=vault_client,
    )
    return build_graph(toolkit)
