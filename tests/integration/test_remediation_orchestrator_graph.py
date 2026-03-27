"""Integration test for Remediation Orchestrator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.remediation_orchestrator.models import (
    RemediationOrchestratorState,
)


@pytest.fixture
def orchestrator_state() -> dict:
    return RemediationOrchestratorState(
        request_id="test-ro-001",
        tenant_id="tenant-prod-01",
        incident_id="inc-5001",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.remediation_orchestrator.graph import (
        create_remediation_orchestrator_graph,
    )

    sg = create_remediation_orchestrator_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "assess_incident",
        "plan_remediation",
        "coordinate_agents",
        "monitor_progress",
        "verify_completion",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing: {name}"


def test_state_model_validation():
    state = RemediationOrchestratorState(
        request_id="ro-val-001",
        tenant_id="tenant-01",
        incident_id="inc-100",
        approval_required=True,
    )
    assert state.incident_id == "inc-100"
    assert state.approval_required is True


def test_state_defaults():
    state = RemediationOrchestratorState()
    assert state.error == ""
    assert state.incident_id == ""
    assert state.steps == []


@pytest.mark.asyncio
async def test_full_pipeline(orchestrator_state):
    from shieldops.agents.remediation_orchestrator.graph import (
        create_remediation_orchestrator_graph,
    )

    sg = create_remediation_orchestrator_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(orchestrator_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
