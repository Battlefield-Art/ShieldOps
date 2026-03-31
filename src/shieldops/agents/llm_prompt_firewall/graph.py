"""LangGraph workflow definition for the LLM Prompt
Firewall Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.llm_prompt_firewall.models import (
    LLMPromptFirewallState,
)
from shieldops.agents.llm_prompt_firewall.nodes import (
    analyze_intent,
    classify_risk,
    detect_injection,
    enforce_policy,
    generate_report,
    intercept_prompt,
)
from shieldops.agents.tracing import traced_node

_AGENT = "llm_prompt_firewall"


def _should_enforce(
    state: LLMPromptFirewallState,
) -> str:
    """Route after risk classification: enforce if
    injections detected, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.injections_detected > 0:
        return "enforce_policy"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the LLM Prompt Firewall LangGraph workflow.

    Workflow:
        intercept_prompt -> analyze_intent
            -> detect_injection -> classify_risk
            -> [injections? -> enforce_policy]
            -> generate_report -> END
    """
    graph = StateGraph(LLMPromptFirewallState)

    graph.add_node(
        "intercept_prompt",
        traced_node(f"{_AGENT}.intercept_prompt", _AGENT)(intercept_prompt),
    )
    graph.add_node(
        "analyze_intent",
        traced_node(f"{_AGENT}.analyze_intent", _AGENT)(analyze_intent),
    )
    graph.add_node(
        "detect_injection",
        traced_node(f"{_AGENT}.detect_injection", _AGENT)(detect_injection),
    )
    graph.add_node(
        "classify_risk",
        traced_node(f"{_AGENT}.classify_risk", _AGENT)(classify_risk),
    )
    graph.add_node(
        "enforce_policy",
        traced_node(f"{_AGENT}.enforce_policy", _AGENT)(enforce_policy),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("intercept_prompt")
    graph.add_edge("intercept_prompt", "analyze_intent")
    graph.add_edge("analyze_intent", "detect_injection")
    graph.add_edge("detect_injection", "classify_risk")
    graph.add_conditional_edges(
        "classify_risk",
        _should_enforce,
        {
            "enforce_policy": "enforce_policy",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policy", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_llm_prompt_firewall_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an LLM Prompt Firewall
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
