"""LangGraph workflow for the Config Remediation Agent."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ConfigRemediationState
from .nodes import (
    apply_fixes,
    generate_fixes,
    generate_report,
    identify_misconfigs,
    scan_configurations,
    verify_fixes,
)


def build_graph():  # type: ignore[no-untyped-def]
    """Build the config_remediation agent graph (linear sequence)."""
    return build_linear_graph(
        ConfigRemediationState,
        [
            ("scan_configurations", scan_configurations),
            ("identify_misconfigs", identify_misconfigs),
            ("generate_fixes", generate_fixes),
            ("apply_fixes", apply_fixes),
            ("verify_fixes", verify_fixes),
            ("generate_report", generate_report),
        ],
    )


def create_config_remediation_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create a Config Remediation graph."""
    return build_graph()
