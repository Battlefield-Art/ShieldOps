"""LangGraph workflow definition for the Prompt Shield Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.prompt_shield.models import PromptShieldState
from shieldops.agents.prompt_shield.nodes import (
    analyze_jailbreaks,
    classify_threats,
    detect_injections,
    enforce_policies,
    generate_report,
    ingest_prompts,
)
from shieldops.agents.prompt_shield.tools import PromptShieldToolkit
from shieldops.agents.tracing import traced_node


def should_enforce(state: PromptShieldState) -> str:
    """Route to enforcement if any detections or jailbreaks found, else skip to report."""
    if state.error:
        return "generate_report"
    if state.injection_detections or state.jailbreak_attempts:
        return "enforce_policies"
    return "generate_report"


def build_graph(toolkit: PromptShieldToolkit) -> StateGraph:  # noqa: ARG001
    """Build the Prompt Shield Agent LangGraph workflow.

    Workflow:
        ingest_prompts -> classify_threats -> detect_injections
            -> analyze_jailbreaks -> [detections? -> enforce_policies]
            -> generate_report -> END
    """
    graph = StateGraph(PromptShieldState)

    _agent = "prompt_shield"
    graph.add_node(
        "ingest_prompts",
        traced_node("prompt_shield.ingest_prompts", _agent)(ingest_prompts),
    )
    graph.add_node(
        "classify_threats",
        traced_node("prompt_shield.classify_threats", _agent)(classify_threats),
    )
    graph.add_node(
        "detect_injections",
        traced_node("prompt_shield.detect_injections", _agent)(detect_injections),
    )
    graph.add_node(
        "analyze_jailbreaks",
        traced_node("prompt_shield.analyze_jailbreaks", _agent)(analyze_jailbreaks),
    )
    graph.add_node(
        "enforce_policies",
        traced_node("prompt_shield.enforce_policies", _agent)(enforce_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node("prompt_shield.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("ingest_prompts")
    graph.add_edge("ingest_prompts", "classify_threats")
    graph.add_edge("classify_threats", "detect_injections")
    graph.add_edge("detect_injections", "analyze_jailbreaks")
    graph.add_conditional_edges(
        "analyze_jailbreaks",
        should_enforce,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_prompt_shield_graph(
    **clients: Any,
) -> StateGraph:
    """Factory to create the Prompt Shield graph with injected dependencies."""
    toolkit = PromptShieldToolkit(
        policy_engine=clients.get("policy_engine"),
        threat_intel=clients.get("threat_intel"),
        repository=clients.get("repository"),
    )
    return build_graph(toolkit)
