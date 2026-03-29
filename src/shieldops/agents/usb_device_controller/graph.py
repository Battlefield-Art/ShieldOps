"""USB Device Controller Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import USBDeviceControllerState
from .nodes import (
    check_whitelist,
    enforce_policy,
    generate_report,
    monitor_transfers,
    scan_devices,
)
from .tools import USBDeviceControllerToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: USBDeviceControllerToolkit,
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
    toolkit: USBDeviceControllerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the USB Device Controller agent graph."""

    graph = StateGraph(USBDeviceControllerState)

    graph.add_node("scan_devices", _traced_node(scan_devices, toolkit))
    graph.add_node("check_whitelist", _traced_node(check_whitelist, toolkit))
    graph.add_node("monitor_transfers", _traced_node(monitor_transfers, toolkit))
    graph.add_node("enforce_policy", _traced_node(enforce_policy, toolkit))
    graph.add_node("report", _traced_node(generate_report, toolkit))
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("scan_devices")
    graph.add_conditional_edges(
        "scan_devices",
        _check_error,
        {"continue": "check_whitelist", "error_end": "error_end"},
    )
    graph.add_edge("check_whitelist", "monitor_transfers")
    graph.add_edge("monitor_transfers", "enforce_policy")
    graph.add_edge("enforce_policy", "report")
    graph.add_edge("report", END)
    graph.add_edge("error_end", END)

    return graph


def create_usb_device_controller_graph(
    endpoint_client: Any | None = None,
    dlp_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the USB Device Controller graph with deps."""
    toolkit = USBDeviceControllerToolkit(
        endpoint_client=endpoint_client,
        dlp_client=dlp_client,
    )
    return build_graph(toolkit)
