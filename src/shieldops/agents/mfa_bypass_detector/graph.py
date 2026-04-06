"""MFA Bypass Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import MFABypassDetectorState
from .nodes import (
    analyze_patterns,
    apply_remediation,
    assess_risk,
    collect_auth_events,
    detect_mfa_bypass,
    generate_report,
)
from .tools import MFABypassDetectorToolkit


def build_graph(toolkit: MFABypassDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the mfa_bypass_detector agent graph (linear sequence)."""
    return build_linear_graph(
        MFABypassDetectorState,
        [
            ("collect_auth_events", collect_auth_events),
            ("analyze_patterns", analyze_patterns),
            ("detect_bypass", detect_mfa_bypass),
            ("assess_risk", assess_risk),
            ("remediate", apply_remediation),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_mfa_bypass_detector_graph(
    identity_provider: Any | None = None,
    siem_connector: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the MFA Bypass Detector graph."""
    toolkit = MFABypassDetectorToolkit(
        identity_provider=identity_provider,
        siem_connector=siem_connector,
    )
    return build_graph(toolkit)
