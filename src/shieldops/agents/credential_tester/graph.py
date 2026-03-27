"""LangGraph workflow for the Credential Tester Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.credential_tester.models import (
    CredentialTesterState,
)
from shieldops.agents.credential_tester.nodes import (
    assess_risk,
    audit_password_policies,
    check_leaked_credentials,
    generate_report,
    test_credential_rotation,
    test_mfa_coverage,
)
from shieldops.agents.credential_tester.tools import (
    CredentialTesterToolkit,
)
from shieldops.agents.tracing import traced_node

_AGENT = "credential_tester"


def _has_leaked(
    state: CredentialTesterState,
) -> str:
    """Route based on leaked credential findings."""
    if state.error:
        return "generate_report"
    leaked = [r for r in state.leaked_found if r.get("is_leaked")]
    if leaked:
        return "test_mfa_coverage"
    return "test_mfa_coverage"


def build_graph(
    toolkit: CredentialTesterToolkit,
) -> StateGraph:
    """Build the credential tester LangGraph workflow.

    Workflow:
        audit_password_policies
            -> check_leaked_credentials
            -> test_mfa_coverage
            -> test_credential_rotation
            -> assess_risk
            -> generate_report -> END
    """
    graph = StateGraph(CredentialTesterState)

    async def _policies(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await audit_password_policies(state, toolkit)

    async def _leaked(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await check_leaked_credentials(state, toolkit)

    async def _mfa(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await test_mfa_coverage(state, toolkit)

    async def _rotation(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await test_credential_rotation(state, toolkit)

    async def _risk(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await assess_risk(state, toolkit)

    async def _report(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await generate_report(state, toolkit)

    graph.add_node(
        "audit_password_policies",
        traced_node(f"{_AGENT}.audit_password_policies", _AGENT)(_policies),
    )
    graph.add_node(
        "check_leaked_credentials",
        traced_node(f"{_AGENT}.check_leaked_credentials", _AGENT)(_leaked),
    )
    graph.add_node(
        "test_mfa_coverage",
        traced_node(f"{_AGENT}.test_mfa_coverage", _AGENT)(_mfa),
    )
    graph.add_node(
        "test_credential_rotation",
        traced_node(f"{_AGENT}.test_credential_rotation", _AGENT)(_rotation),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(_report),
    )

    graph.set_entry_point("audit_password_policies")
    graph.add_edge(
        "audit_password_policies",
        "check_leaked_credentials",
    )
    graph.add_conditional_edges(
        "check_leaked_credentials",
        _has_leaked,
        {
            "test_mfa_coverage": "test_mfa_coverage",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "test_mfa_coverage",
        "test_credential_rotation",
    )
    graph.add_edge("test_credential_rotation", "assess_risk")
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_credential_tester_graph(
    **clients: Any,
) -> StateGraph:
    """Factory to create a credential tester graph."""
    toolkit = CredentialTesterToolkit(
        identity_provider=clients.get("identity_provider"),
        hibp_client=clients.get("hibp_client"),
        policy_engine=clients.get("policy_engine"),
        repository=clients.get("repository"),
    )
    return build_graph(toolkit)
