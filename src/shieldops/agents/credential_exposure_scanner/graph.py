"""Credential Exposure Scanner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CredentialExposureScannerState
from .nodes import (
    assess_exposure,
    classify_type,
    detect_credentials,
    generate_report,
    scan_sources,
    trigger_rotation,
)
from .tools import CredentialExposureScannerToolkit


def build_graph(toolkit: CredentialExposureScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the credential_exposure_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        CredentialExposureScannerState,
        [
            ("scan_sources", scan_sources),
            ("detect_credentials", detect_credentials),
            ("classify_type", classify_type),
            ("assess_exposure", assess_exposure),
            ("trigger_rotation", trigger_rotation),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_credential_exposure_scanner_graph(
    scan_api: Any | None = None,
    rotation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Credential Exposure Scanner graph."""
    toolkit = CredentialExposureScannerToolkit(
        scan_api=scan_api,
        rotation_api=rotation_api,
    )
    return build_graph(toolkit)
