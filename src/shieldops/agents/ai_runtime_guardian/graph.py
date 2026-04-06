"""AI Runtime Guardian Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AIRuntimeGuardianState
from .nodes import (
    analyze_model_behavior,
    detect_prompt_attacks,
    enforce_guardrails,
    guard_tool_execution,
    monitor_ai_runtime,
    report,
)
from .tools import AIRuntimeGuardianToolkit


def build_graph(toolkit: AIRuntimeGuardianToolkit):  # type: ignore[no-untyped-def]
    """Build the ai_runtime_guardian agent graph (linear sequence)."""
    return build_linear_graph(
        AIRuntimeGuardianState,
        [
            ("monitor_ai_runtime", monitor_ai_runtime),
            ("detect_prompt_attacks", detect_prompt_attacks),
            ("analyze_model_behavior", analyze_model_behavior),
            ("guard_tool_execution", guard_tool_execution),
            ("enforce_guardrails", enforce_guardrails),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_ai_runtime_guardian_graph(
    runtime_api: Any | None = None,
    threat_feed: Any | None = None,
    policy_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the AI Runtime Guardian graph."""
    toolkit = AIRuntimeGuardianToolkit(
        runtime_api=runtime_api,
        threat_feed=threat_feed,
        policy_engine=policy_engine,
    )
    return build_graph(toolkit)
