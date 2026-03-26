"""Data Loss Prevention Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataLossPreventionState
from .nodes import (
    classify_sensitive_data,
    detect_exfiltration,
    discover_data_flows,
    enforce_policies,
    report,
    respond_to_incidents,
)
from .tools import DataLossPreventionToolkit


def _has_exfiltration(state: Any) -> str:
    """Route based on whether exfiltration attempts exist."""
    if hasattr(state, "exfiltration_attempts"):
        attempts = state.exfiltration_attempts
    else:
        attempts = state.get("exfiltration_attempts", [])
    if attempts:
        return "enforce"
    return "report"


def build_graph(
    toolkit: DataLossPreventionToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Loss Prevention agent graph.

    Flow: discover_data_flows -> classify_sensitive_data
          -> detect_exfiltration -> (attempts?)
          -> enforce_policies -> respond_to_incidents
          -> report | report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_data_flows(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_sensitive_data(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_exfiltration(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _respond(state: Any) -> dict[str, Any]:
        return await respond_to_incidents(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(DataLossPreventionState)
    graph.add_node("discover_data_flows", _discover)
    graph.add_node("classify_sensitive_data", _classify)
    graph.add_node("detect_exfiltration", _detect)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("respond_to_incidents", _respond)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_data_flows")
    graph.add_edge("discover_data_flows", "classify_sensitive_data")
    graph.add_edge("classify_sensitive_data", "detect_exfiltration")
    graph.add_conditional_edges(
        "detect_exfiltration",
        _has_exfiltration,
        {"enforce": "enforce_policies", "report": "report"},
    )
    graph.add_edge("enforce_policies", "respond_to_incidents")
    graph.add_edge("respond_to_incidents", "report")
    graph.add_edge("report", END)

    return graph


def create_data_loss_prevention_graph(
    endpoint_connector: Any | None = None,
    cloud_connector: Any | None = None,
    browser_connector: Any | None = None,
    ai_pipeline_connector: Any | None = None,
    mcp_connector: Any | None = None,
    policy_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DLP graph with dependencies."""
    toolkit = DataLossPreventionToolkit(
        endpoint_connector=endpoint_connector,
        cloud_connector=cloud_connector,
        browser_connector=browser_connector,
        ai_pipeline_connector=ai_pipeline_connector,
        mcp_connector=mcp_connector,
        policy_engine=policy_engine,
    )
    return build_graph(toolkit)
