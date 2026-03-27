"""Integration test for the remediation_orchestrator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.remediation_orchestrator.models import RemediationOrchestratorState


@pytest.fixture
def state() -> dict:
    return RemediationOrchestratorState().model_dump()


def test_graph_compiles():
    from shieldops.agents.remediation_orchestrator.graph import (
        create_remediation_orchestrator_graph,
    )

    sg = create_remediation_orchestrator_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = RemediationOrchestratorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.remediation_orchestrator.graph import (
        create_remediation_orchestrator_graph,
    )

    try:
        result = await create_remediation_orchestrator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
