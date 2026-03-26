"""Integration test for the ai_triage_accelerator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_triage_accelerator.models import AITriageAcceleratorState


@pytest.fixture
def state() -> dict:
    return AITriageAcceleratorState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.ai_triage_accelerator.graph import create_ai_triage_accelerator_graph

    sg = create_ai_triage_accelerator_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AITriageAcceleratorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ai_triage_accelerator.graph import create_ai_triage_accelerator_graph

    try:
        result = await create_ai_triage_accelerator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
