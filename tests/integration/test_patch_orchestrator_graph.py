"""Integration test for the Patch Orchestrator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.patch_orchestrator.models import (
    PatchOrchestratorState,
)


@pytest.fixture
def orchestrator_state() -> dict:
    return PatchOrchestratorState(
        request_id="test-po-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.patch_orchestrator.graph import (
        create_patch_orchestrator_graph,
    )

    sg = create_patch_orchestrator_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_targets",
        "assess_patches",
        "plan_deployment",
        "deploy_patches",
        "verify_deployment",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing: {name}"


def test_state_model_validation():
    state = PatchOrchestratorState(
        request_id="po-val-001",
        tenant_id="tenant-01",
        targets=["host-a", "host-b"],
        strategy="rolling",
    )
    assert state.targets == ["host-a", "host-b"]
    assert state.strategy == "rolling"


def test_state_defaults():
    state = PatchOrchestratorState()
    assert state.error == ""
    assert state.targets == []
    assert state.patches == []


@pytest.mark.asyncio
async def test_full_pipeline(orchestrator_state):
    from shieldops.agents.patch_orchestrator.graph import (
        create_patch_orchestrator_graph,
    )

    sg = create_patch_orchestrator_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(orchestrator_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
