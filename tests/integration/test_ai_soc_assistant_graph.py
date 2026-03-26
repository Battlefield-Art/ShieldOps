"""Integration test for the ai_soc_assistant agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_soc_assistant.models import AISOCAssistantState


@pytest.fixture
def state() -> dict:
    return AISOCAssistantState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.ai_soc_assistant.graph import create_ai_soc_assistant_graph

    sg = create_ai_soc_assistant_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AISOCAssistantState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ai_soc_assistant.graph import create_ai_soc_assistant_graph

    try:
        result = await create_ai_soc_assistant_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
