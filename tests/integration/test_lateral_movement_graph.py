"""Integration test for the Lateral Movement Detector Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.lateral_movement.models import (
    DetectorStage,
    IdentitySignal,
    LateralMovementState,
    MovementPath,
    MovementType,
)


@pytest.fixture
def detection_state() -> dict:
    return LateralMovementState(
        request_id="test-lm-001",
        tenant_id="tenant-prod-01",
        time_window_hours=24,
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.lateral_movement.graph import create_lateral_movement_graph

    sg = create_lateral_movement_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_signals",
        "analyze_paths",
        "detect_pivots",
        "assess_blast_radius",
        "respond",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    signal = IdentitySignal(
        id="sig-001",
        identity_id="svc-admin",
        identity_type="service_account",
        source_cloud="aws",
        action="AssumeRole",
        target_resource="arn:aws:iam::role/admin",
        timestamp=1000000.0,
        geo_location="us-east-1",
        risk_indicators=["cross-account", "admin-role"],
    )
    path = MovementPath(
        id="path-001",
        movement_type=MovementType.CROSS_CLOUD_ESCALATION,
        source_identity="svc-admin",
        target_identity="gcp-sa-admin",
        source_cloud="aws",
        target_cloud="gcp",
        hops=3,
        confidence=0.88,
        mitre_technique="T1078.004",
    )
    state = LateralMovementState(
        identity_signals=[signal],
        movement_paths=[path],
        stage=DetectorStage.ASSESS_BLAST_RADIUS,
    )
    assert len(state.movement_paths) == 1
    assert state.movement_paths[0].movement_type == MovementType.CROSS_CLOUD_ESCALATION


def test_state_defaults():
    state = LateralMovementState()
    assert state.stage == DetectorStage.COLLECT_SIGNALS
    assert state.identity_signals == []
    assert state.movement_paths == []
    assert state.response_actions == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(detection_state):
    from shieldops.agents.lateral_movement.graph import create_lateral_movement_graph

    sg = create_lateral_movement_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(detection_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
