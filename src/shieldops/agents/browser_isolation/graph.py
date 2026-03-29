"""Browser Isolation Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import BrowserIsolationState
from .nodes import (
    collect_sessions,
    detect_breakouts,
    evaluate_policies,
    generate_report,
    sandbox_content,
)
from .tools import BrowserIsolationToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: BrowserIsolationToolkit,
) -> Any:
    async def _wrapper(state: Any) -> dict[str, Any]:
        d = state.model_dump() if hasattr(state, "model_dump") else dict(state)
        try:
            return await func(d, toolkit)
        except Exception as exc:
            return {"error": str(exc)}

    return _wrapper


def _check_error(state: Any) -> str:
    err = state.error if hasattr(state, "error") else state.get("error", "")
    return "error_end" if err else "continue"


def build_graph(
    toolkit: BrowserIsolationToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Browser Isolation agent graph."""

    graph = StateGraph(BrowserIsolationState)

    graph.add_node("collect_sessions", _traced_node(collect_sessions, toolkit))
    graph.add_node("detect_breakouts", _traced_node(detect_breakouts, toolkit))
    graph.add_node("evaluate_policies", _traced_node(evaluate_policies, toolkit))
    graph.add_node("sandbox_content", _traced_node(sandbox_content, toolkit))
    graph.add_node("report", _traced_node(generate_report, toolkit))
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("collect_sessions")
    graph.add_conditional_edges(
        "collect_sessions",
        _check_error,
        {"continue": "detect_breakouts", "error_end": "error_end"},
    )
    graph.add_edge("detect_breakouts", "evaluate_policies")
    graph.add_edge("evaluate_policies", "sandbox_content")
    graph.add_edge("sandbox_content", "report")
    graph.add_edge("report", END)
    graph.add_edge("error_end", END)

    return graph


def create_browser_isolation_graph(
    isolation_client: Any | None = None,
    proxy_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Browser Isolation graph with deps."""
    toolkit = BrowserIsolationToolkit(
        isolation_client=isolation_client,
        proxy_client=proxy_client,
    )
    return build_graph(toolkit)
