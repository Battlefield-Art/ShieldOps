"""AI Runtime Guardian Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: AIRuntimeGuardianToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the AI Runtime Guardian agent graph.

    Flow:
        monitor_ai_runtime -> detect_prompt_attacks
        -> analyze_model_behavior
        -> guard_tool_execution
        -> enforce_guardrails -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _monitor(
        state: Any,
    ) -> dict[str, Any]:
        return await monitor_ai_runtime(_to_dict(state), toolkit)

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_prompt_attacks(_to_dict(state), toolkit)

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_model_behavior(_to_dict(state), toolkit)

    async def _guard(
        state: Any,
    ) -> dict[str, Any]:
        return await guard_tool_execution(_to_dict(state), toolkit)

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_guardrails(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(AIRuntimeGuardianState)
    graph.add_node("monitor_ai_runtime", _monitor)
    graph.add_node("detect_prompt_attacks", _detect)
    graph.add_node("analyze_model_behavior", _analyze)
    graph.add_node("guard_tool_execution", _guard)
    graph.add_node("enforce_guardrails", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("monitor_ai_runtime")
    graph.add_edge(
        "monitor_ai_runtime",
        "detect_prompt_attacks",
    )
    graph.add_edge(
        "detect_prompt_attacks",
        "analyze_model_behavior",
    )
    graph.add_edge(
        "analyze_model_behavior",
        "guard_tool_execution",
    )
    graph.add_edge(
        "guard_tool_execution",
        "enforce_guardrails",
    )
    graph.add_edge("enforce_guardrails", "report")
    graph.add_edge("report", END)

    return graph


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
