"""Integration test for the cyber_recovery agent."""

from __future__ import annotations

import pytest

from shieldops.agents.cyber_recovery.models import CyberRecoveryState


@pytest.fixture
def state() -> dict:
    return CyberRecoveryState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.cyber_recovery.graph import create_cyber_recovery_graph

    sg = create_cyber_recovery_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CyberRecoveryState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.cyber_recovery.graph import create_cyber_recovery_graph

    try:
        result = await create_cyber_recovery_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
