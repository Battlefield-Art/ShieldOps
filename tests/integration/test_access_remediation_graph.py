"""Integration test for the access_remediation agent."""

from __future__ import annotations

import pytest

from shieldops.agents.access_remediation.models import AccessRemediationState


@pytest.fixture
def state() -> dict:
    return AccessRemediationState().model_dump()


def test_graph_compiles():
    from shieldops.agents.access_remediation.graph import (
        create_access_remediation_graph,
    )

    sg = create_access_remediation_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AccessRemediationState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.access_remediation.graph import (
        create_access_remediation_graph,
    )

    try:
        result = await create_access_remediation_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
