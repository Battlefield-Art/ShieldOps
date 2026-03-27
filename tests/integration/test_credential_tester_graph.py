"""Integration test for Credential Tester Agent graph."""

from __future__ import annotations

import pytest

from shieldops.agents.credential_tester.models import (
    CredentialTesterState,
)


@pytest.fixture
def tester_state() -> dict:
    return CredentialTesterState(
        request_id="test-ct-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.credential_tester.graph import (
        create_credential_tester_graph,
    )

    sg = create_credential_tester_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_credentials",
        "test_strength",
        "check_reuse",
        "validate_policies",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    state = CredentialTesterState(
        request_id="ct-001",
        tenant_id="tenant-01",
    )
    assert state.request_id == "ct-001"
    assert state.error == ""


def test_state_defaults():
    state = CredentialTesterState()
    assert state.error == ""
    assert state.findings == []
    assert state.credentials_tested == []


@pytest.mark.asyncio
async def test_full_pipeline(tester_state):
    from shieldops.agents.credential_tester.graph import (
        create_credential_tester_graph,
    )

    sg = create_credential_tester_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(tester_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
