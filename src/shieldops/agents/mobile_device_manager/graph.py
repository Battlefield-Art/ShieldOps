"""Mobile Device Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import MobileDeviceManagerState
from .nodes import (
    assess_compliance,
    check_apps,
    check_enrollment,
    discover_devices,
    enforce_policies,
    generate_report,
)
from .tools import MobileDeviceManagerToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: MobileDeviceManagerToolkit,
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
    toolkit: MobileDeviceManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Mobile Device Manager agent graph."""

    graph = StateGraph(MobileDeviceManagerState)

    graph.add_node("discover_devices", _traced_node(discover_devices, toolkit))
    graph.add_node("check_enrollment", _traced_node(check_enrollment, toolkit))
    graph.add_node("assess_compliance", _traced_node(assess_compliance, toolkit))
    graph.add_node("check_apps", _traced_node(check_apps, toolkit))
    graph.add_node("enforce_policies", _traced_node(enforce_policies, toolkit))
    graph.add_node("report", _traced_node(generate_report, toolkit))
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("discover_devices")
    graph.add_conditional_edges(
        "discover_devices",
        _check_error,
        {"continue": "check_enrollment", "error_end": "error_end"},
    )
    graph.add_edge("check_enrollment", "assess_compliance")
    graph.add_edge("assess_compliance", "check_apps")
    graph.add_edge("check_apps", "enforce_policies")
    graph.add_edge("enforce_policies", "report")
    graph.add_edge("report", END)
    graph.add_edge("error_end", END)

    return graph


def create_mobile_device_manager_graph(
    mdm_client: Any | None = None,
    directory_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Mobile Device Manager graph with deps."""
    toolkit = MobileDeviceManagerToolkit(
        mdm_client=mdm_client,
        directory_client=directory_client,
    )
    return build_graph(toolkit)
