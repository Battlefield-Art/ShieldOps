"""SaaS Security Posture Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SaaSSecurityPostureState
from .nodes import (
    assess_risk,
    audit_config,
    check_sharing,
    discover_apps,
    generate_report,
    remediate,
)
from .tools import SaaSSecurityPostureToolkit


def build_graph(toolkit: SaaSSecurityPostureToolkit):  # type: ignore[no-untyped-def]
    """Build the saas_security_posture agent graph (linear sequence)."""
    return build_linear_graph(
        SaaSSecurityPostureState,
        [
            ("discover_apps", discover_apps),
            ("audit_config", audit_config),
            ("check_sharing", check_sharing),
            ("assess_risk", assess_risk),
            ("remediate", remediate),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_saas_security_posture_graph(
    saas_api: Any | None = None,
    identity_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SaaS Security Posture graph."""
    toolkit = SaaSSecurityPostureToolkit(
        saas_api=saas_api,
        identity_provider=identity_provider,
    )
    return build_graph(toolkit)
