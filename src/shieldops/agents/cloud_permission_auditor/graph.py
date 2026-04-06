"""Cloud Permission Auditor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CloudPermissionAuditorState
from .nodes import (
    analyze_scope,
    collect_permissions,
    detect_violations,
    generate_fixes,
    generate_report,
    map_cross_account,
)
from .tools import CloudPermissionAuditorToolkit


def build_graph(toolkit: CloudPermissionAuditorToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_permission_auditor agent graph (linear sequence)."""
    return build_linear_graph(
        CloudPermissionAuditorState,
        [
            ("collect_permissions", collect_permissions),
            ("analyze_scope", analyze_scope),
            ("detect_violations", detect_violations),
            ("map_cross_account", map_cross_account),
            ("generate_fixes", generate_fixes),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_cloud_permission_auditor_graph(
    iam_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Permission Auditor graph."""
    toolkit = CloudPermissionAuditorToolkit(
        iam_api=iam_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
