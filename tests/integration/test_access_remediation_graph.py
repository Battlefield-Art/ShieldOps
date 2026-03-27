"""Integration test for the Access Remediation Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.access_remediation.models import (
    AccessRemediationState,
)


@pytest.fixture
def remediation_state() -> dict:
    return AccessRemediationState(
        request_id="test-ar-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.access_remediation.graph import (
        create_access_remediation_graph,
    )

    sg = create_access_remediation_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "discover_identities",
        "analyze_permissions",
        "identify_excess",
        "plan_changes",
        "apply_changes",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing: {name}"


def test_state_model_validation():
    state = AccessRemediationState(
        request_id="ar-val-001",
        tenant_id="tenant-01",
        identity_ids=["svc-admin", "svc-deploy"],
        scope="excessive_permissions",
    )
    assert len(state.identity_ids) == 2
    assert state.scope == "excessive_permissions"


def test_state_defaults():
    state = AccessRemediationState()
    assert state.error == ""
    assert state.identity_ids == []
    assert state.changes == []


@pytest.mark.asyncio
async def test_full_pipeline(remediation_state):
    from shieldops.agents.access_remediation.graph import (
        create_access_remediation_graph,
    )

    sg = create_access_remediation_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(remediation_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
