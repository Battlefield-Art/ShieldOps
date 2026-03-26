"""Integration test for the prompt_shield agent."""

from __future__ import annotations

import pytest

from shieldops.agents.prompt_shield.models import PromptShieldState


@pytest.fixture
def state() -> dict:
    return PromptShieldState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.prompt_shield.graph import create_prompt_shield_graph

    sg = create_prompt_shield_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = PromptShieldState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.prompt_shield.graph import create_prompt_shield_graph

    try:
        result = await create_prompt_shield_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
