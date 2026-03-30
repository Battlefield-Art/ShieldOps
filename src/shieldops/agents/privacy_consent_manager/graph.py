"""Privacy Consent Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

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

_AGENT = "privacy_consent_manager"


def _check_error(
    state: PrivacyConsentManagerState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: PrivacyConsentManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Privacy Consent Manager graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_consents(
            _to_dict(state),
            toolkit,
        )

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_records(
            _to_dict(state),
            toolkit,
        )

    async def _expiry(
        state: Any,
    ) -> dict[str, Any]:
        return await check_expiry(
            _to_dict(state),
            toolkit,
        )

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_preferences(
            _to_dict(state),
            toolkit,
        )

    async def _audit(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_compliance(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(PrivacyConsentManagerState)
    graph.add_node(
        "discover_consents",
        traced_node("pcm.discover", _AGENT)(_discover),
    )
    graph.add_node(
        "validate_records",
        traced_node("pcm.validate", _AGENT)(_validate),
    )
    graph.add_node(
        "check_expiry",
        traced_node("pcm.expiry", _AGENT)(_expiry),
    )
    graph.add_node(
        "enforce_preferences",
        traced_node("pcm.enforce", _AGENT)(_enforce),
    )
    graph.add_node(
        "audit_compliance",
        traced_node("pcm.audit", _AGENT)(_audit),
    )
    graph.add_node(
        "report",
        traced_node("pcm.report", _AGENT)(_report),
    )

    graph.set_entry_point("discover_consents")
    graph.add_edge(
        "discover_consents",
        "validate_records",
    )
    graph.add_edge("validate_records", "check_expiry")
    graph.add_edge(
        "check_expiry",
        "enforce_preferences",
    )
    graph.add_edge(
        "enforce_preferences",
        "audit_compliance",
    )
    graph.add_edge("audit_compliance", "report")
    graph.add_edge("report", END)

    return graph


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
