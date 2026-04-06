"""Security Awareness Engine Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityAwarenessEngineState
from .nodes import (
    analyze_phishing,
    assess_baseline,
    evaluate_training,
    generate_plan,
    generate_report,
    identify_risks,
)
from .tools import SecurityAwarenessEngineToolkit


def build_graph(toolkit: SecurityAwarenessEngineToolkit):  # type: ignore[no-untyped-def]
    """Build the security_awareness_engine agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityAwarenessEngineState,
        [
            ("assess_baseline", assess_baseline),
            ("analyze_phishing", analyze_phishing),
            ("evaluate_training", evaluate_training),
            ("identify_risks", identify_risks),
            ("generate_plan", generate_plan),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_awareness_engine_graph(
    lms_client: Any | None = None,
    phishing_client: Any | None = None,
    hr_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Security Awareness Engine graph."""
    toolkit = SecurityAwarenessEngineToolkit(
        lms_client=lms_client,
        phishing_client=phishing_client,
        hr_client=hr_client,
    )
    return build_graph(toolkit)
