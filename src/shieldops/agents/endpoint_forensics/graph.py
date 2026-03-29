"""Endpoint Forensics Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import EndpointForensicsState
from .nodes import (
    analyze_memory,
    carve_files,
    collect_artifacts,
    generate_report,
    investigate_processes,
    reconstruct_timeline,
)
from .tools import EndpointForensicsToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: EndpointForensicsToolkit,
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
    toolkit: EndpointForensicsToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Endpoint Forensics agent graph."""

    graph = StateGraph(EndpointForensicsState)

    graph.add_node("collect_artifacts", _traced_node(collect_artifacts, toolkit))
    graph.add_node("analyze_memory", _traced_node(analyze_memory, toolkit))
    graph.add_node(
        "investigate_processes",
        _traced_node(investigate_processes, toolkit),
    )
    graph.add_node("carve_files", _traced_node(carve_files, toolkit))
    graph.add_node(
        "reconstruct_timeline",
        _traced_node(reconstruct_timeline, toolkit),
    )
    graph.add_node("report", _traced_node(generate_report, toolkit))
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("collect_artifacts")
    graph.add_conditional_edges(
        "collect_artifacts",
        _check_error,
        {"continue": "analyze_memory", "error_end": "error_end"},
    )
    graph.add_edge("analyze_memory", "investigate_processes")
    graph.add_edge("investigate_processes", "carve_files")
    graph.add_edge("carve_files", "reconstruct_timeline")
    graph.add_edge("reconstruct_timeline", "report")
    graph.add_edge("report", END)
    graph.add_edge("error_end", END)

    return graph


def create_endpoint_forensics_graph(
    edr_client: Any | None = None,
    forensics_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Forensics graph with deps."""
    toolkit = EndpointForensicsToolkit(
        edr_client=edr_client,
        forensics_client=forensics_client,
    )
    return build_graph(toolkit)
