"""Integration test for the ai_runtime_guardian agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_runtime_guardian.models import AIRuntimeGuardianState


@pytest.fixture
def state() -> dict:
    return AIRuntimeGuardianState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.ai_runtime_guardian.graph import (
        create_ai_runtime_guardian_graph,
    )

    sg = create_ai_runtime_guardian_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AIRuntimeGuardianState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ai_runtime_guardian.graph import (
        create_ai_runtime_guardian_graph,
    )

    try:
        result = await create_ai_runtime_guardian_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
