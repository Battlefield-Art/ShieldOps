"""Privacy Consent Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import PrivacyConsentManagerState
from .nodes import (
    audit_compliance,
    check_expiry,
    discover_consents,
    enforce_preferences,
    report,
    validate_records,
)
from .tools import PrivacyConsentManagerToolkit


def build_graph(toolkit: PrivacyConsentManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the privacy_consent_manager agent graph (linear sequence)."""
    return build_linear_graph(
        PrivacyConsentManagerState,
        [
            ("discover_consents", discover_consents),
            ("validate_records", validate_records),
            ("check_expiry", check_expiry),
            ("enforce_preferences", enforce_preferences),
            ("audit_compliance", audit_compliance),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_privacy_consent_manager_graph(
    consent_store: Any | None = None,
    preference_api: Any | None = None,
    audit_logger: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Privacy Consent Manager graph."""
    toolkit = PrivacyConsentManagerToolkit(
        consent_store=consent_store,
        preference_api=preference_api,
        audit_logger=audit_logger,
    )
    return build_graph(toolkit)
