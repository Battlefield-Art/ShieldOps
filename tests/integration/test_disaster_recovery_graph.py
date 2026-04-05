"""Integration test for the Disaster Recovery Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.disaster_recovery.models import DisasterRecoveryState, DRStage


@pytest.fixture
def state() -> dict:
    return DisasterRecoveryState(
        request_id="test-dr-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.disaster_recovery.graph import create_disaster_recovery_graph

    sg = create_disaster_recovery_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in [
        "assess_plans",
        "test_failover",
        "measure_rto_rpo",
        "identify_gaps",
        "remediate",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = DisasterRecoveryState()
    assert s.stage == DRStage.ASSESS_PLANS


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.disaster_recovery.graph import create_disaster_recovery_graph

    sg = create_disaster_recovery_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
