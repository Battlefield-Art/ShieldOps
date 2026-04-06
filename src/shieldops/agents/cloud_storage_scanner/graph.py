"""Cloud Storage Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CloudStorageScannerState
from .nodes import (
    assess_encryption,
    detect_sensitive_data,
    discover_buckets,
    generate_report,
    remediate_issues,
    scan_permissions,
)
from .tools import CloudStorageScannerToolkit


def build_graph(toolkit: CloudStorageScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_storage_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        CloudStorageScannerState,
        [
            ("discover_buckets", discover_buckets),
            ("scan_permissions", scan_permissions),
            ("detect_sensitive_data", detect_sensitive_data),
            ("assess_encryption", assess_encryption),
            ("remediate_issues", remediate_issues),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_cloud_storage_scanner_graph(
    cloud_api: Any | None = None,
    scanner_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Storage Scanner graph."""
    toolkit = CloudStorageScannerToolkit(
        cloud_api=cloud_api,
        scanner_api=scanner_api,
    )
    return build_graph(toolkit)
