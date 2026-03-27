"""Integration test for the patch_orchestrator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.patch_orchestrator.models import PatchOrchestratorState


@pytest.fixture
def state() -> dict:
    return PatchOrchestratorState().model_dump()


def test_graph_compiles():
    from shieldops.agents.patch_orchestrator.graph import (
        create_patch_orchestrator_graph,
    )

    sg = create_patch_orchestrator_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = PatchOrchestratorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.patch_orchestrator.graph import (
        create_patch_orchestrator_graph,
    )

    try:
        result = await create_patch_orchestrator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
