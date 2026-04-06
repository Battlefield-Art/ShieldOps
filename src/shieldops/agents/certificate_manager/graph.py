"""Certificate Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CertificateManagerState
from .nodes import (
    check_expiry,
    discover_certs,
    execute_rotation,
    generate_report,
    plan_rotation,
    validate_chains,
)
from .tools import CertificateManagerToolkit


def build_graph(toolkit: CertificateManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the certificate_manager agent graph (linear sequence)."""
    return build_linear_graph(
        CertificateManagerState,
        [
            ("discover_certs", discover_certs),
            ("check_expiry", check_expiry),
            ("validate_chains", validate_chains),
            ("plan_rotation", plan_rotation),
            ("execute_rotation", execute_rotation),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_certificate_manager_graph(
    cert_store: Any | None = None,
    acme_client: Any | None = None,
    dns_client: Any | None = None,
    notification_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Certificate Manager agent graph with dependencies."""
    toolkit = CertificateManagerToolkit(
        cert_store=cert_store,
        acme_client=acme_client,
        dns_client=dns_client,
        notification_client=notification_client,
    )
    return build_graph(toolkit)
