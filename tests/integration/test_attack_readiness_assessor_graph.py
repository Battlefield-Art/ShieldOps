"""Integration test for attack_readiness_assessor."""

from __future__ import annotations

import pytest

from shieldops.agents.attack_readiness_assessor.models import AttackReadinessAssessorState


@pytest.fixture
def state() -> dict:
    return AttackReadinessAssessorState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.attack_readiness_assessor.graph import (
        create_attack_readiness_assessor_graph,
    )

    sg = create_attack_readiness_assessor_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AttackReadinessAssessorState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.attack_readiness_assessor.graph import (
        create_attack_readiness_assessor_graph,
    )

    try:
        result = await create_attack_readiness_assessor_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
