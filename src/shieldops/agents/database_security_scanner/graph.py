"""Database Security Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: DatabaseSecurityScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the database_security_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        DatabaseSecurityScannerState,
        [
            ("discover_databases", discover_databases),
            ("scan_config", scan_configurations),
            ("check_auth", check_authentication),
            ("audit_access", audit_access),
            ("detect_exposure", detect_data_exposure),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
