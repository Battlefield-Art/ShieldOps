"""Database Security Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DatabaseSecurityScannerState
from .nodes import (
    audit_access,
    check_authentication,
    detect_data_exposure,
    discover_databases,
    generate_report,
    scan_configurations,
)
from .tools import DatabaseSecurityScannerToolkit


def build_graph(
    toolkit: DatabaseSecurityScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Database Security Scanner graph.

    Flow:
        discover_databases -> scan_config
        -> check_auth -> audit_access
        -> detect_exposure -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_databases(
            _to_dict(state),
            toolkit,
        )

    async def _scan_config(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_configurations(
            _to_dict(state),
            toolkit,
        )

    async def _check_auth(
        state: Any,
    ) -> dict[str, Any]:
        return await check_authentication(
            _to_dict(state),
            toolkit,
        )

    async def _audit_access(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_access(
            _to_dict(state),
            toolkit,
        )

    async def _detect_exposure(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_data_exposure(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(DatabaseSecurityScannerState)
    graph.add_node("discover_databases", _discover)
    graph.add_node("scan_config", _scan_config)
    graph.add_node("check_auth", _check_auth)
    graph.add_node("audit_access", _audit_access)
    graph.add_node("detect_exposure", _detect_exposure)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_databases")
    graph.add_edge(
        "discover_databases",
        "scan_config",
    )
    graph.add_edge(
        "scan_config",
        "check_auth",
    )
    graph.add_edge(
        "check_auth",
        "audit_access",
    )
    graph.add_edge(
        "audit_access",
        "detect_exposure",
    )
    graph.add_edge(
        "detect_exposure",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_database_security_scanner_graph(
    db_client: Any | None = None,
    scanner_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Database Security Scanner graph."""
    toolkit = DatabaseSecurityScannerToolkit(
        db_client=db_client,
        scanner_api=scanner_api,
    )
    return build_graph(toolkit)
