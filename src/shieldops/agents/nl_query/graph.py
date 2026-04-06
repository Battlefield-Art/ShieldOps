"""LangGraph StateGraph for the Natural Language Query agent."""

from __future__ import annotations

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.nl_query.models import NLQueryState, QueryStage
from shieldops.agents.nl_query.nodes import (
    execute,
    format_output,
    generate_sql,
    handle_error,
    parse_question,
    validate_sql_node,
)
from shieldops.agents.nl_query.tools import NLQueryToolkit

logger = structlog.get_logger()


def _as_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if state else {}


def _route_after_validate(state: Any) -> str:
    s = _as_dict(state)
    if s.get("stage") == QueryStage.FAILED or s.get("error"):
        return "handle_error"
    return "execute"


def _route_after_execute(state: Any) -> str:
    s = _as_dict(state)
    if s.get("stage") == QueryStage.FAILED or s.get("error"):
        return "handle_error"
    return "format_output"


def _route_after_generate(state: Any) -> str:
    s = _as_dict(state)
    if s.get("stage") == QueryStage.FAILED or s.get("error"):
        return "handle_error"
    return "validate_sql"


def build_graph(toolkit: NLQueryToolkit) -> StateGraph:
    """Build the NL query StateGraph wired to the provided toolkit."""

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_question(_as_dict(state), toolkit)

    async def _generate(state: Any) -> dict[str, Any]:
        return await generate_sql(_as_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_sql_node(_as_dict(state), toolkit)

    async def _execute(state: Any) -> dict[str, Any]:
        return await execute(_as_dict(state), toolkit)

    async def _format(state: Any) -> dict[str, Any]:
        return await format_output(_as_dict(state), toolkit)

    async def _error(state: Any) -> dict[str, Any]:
        return await handle_error(_as_dict(state), toolkit)

    graph: StateGraph = StateGraph(NLQueryState)
    graph.add_node("parse_question", _parse)
    graph.add_node("generate_sql", _generate)
    graph.add_node("validate_sql", _validate)
    graph.add_node("execute", _execute)
    graph.add_node("format_output", _format)
    graph.add_node("handle_error", _error)

    graph.set_entry_point("parse_question")
    graph.add_edge("parse_question", "generate_sql")
    graph.add_conditional_edges(
        "generate_sql",
        _route_after_generate,
        {"validate_sql": "validate_sql", "handle_error": "handle_error"},
    )
    graph.add_conditional_edges(
        "validate_sql",
        _route_after_validate,
        {"execute": "execute", "handle_error": "handle_error"},
    )
    graph.add_conditional_edges(
        "execute",
        _route_after_execute,
        {"format_output": "format_output", "handle_error": "handle_error"},
    )
    graph.add_edge("format_output", END)
    graph.add_edge("handle_error", END)

    return graph


def create_nl_query_graph(storage: Any = None) -> StateGraph:
    """Factory that wires up a toolkit and returns a compiled graph builder."""
    toolkit = NLQueryToolkit(storage=storage)
    return build_graph(toolkit)
