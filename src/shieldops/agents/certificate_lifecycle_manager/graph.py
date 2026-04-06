"""Certificate Lifecycle Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CertificateLifecycleManagerState
from .nodes import (
    check_expiry,
    discover_certs,
    execute_renewal,
    generate_report,
    plan_renewal,
    validate_config,
)
from .tools import CertificateLifecycleManagerToolkit


def build_graph(toolkit: CertificateLifecycleManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the certificate_lifecycle_manager agent graph (linear sequence)."""
    return build_linear_graph(
        CertificateLifecycleManagerState,
        [
            ("discover_certs", discover_certs),
            ("check_expiry", check_expiry),
            ("validate_config", validate_config),
            ("plan_renewal", plan_renewal),
            ("execute_renewal", execute_renewal),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_certificate_lifecycle_manager_graph(
    acme_client: Any | None = None,
    scanner_client: Any | None = None,
    vault_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Certificate Lifecycle Manager graph."""
    toolkit = CertificateLifecycleManagerToolkit(
        acme_client=acme_client,
        scanner_client=scanner_client,
        vault_client=vault_client,
    )
    return build_graph(toolkit)
