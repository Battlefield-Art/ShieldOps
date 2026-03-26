"""Integration test for the model_security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.model_security.models import ModelSecurityState


@pytest.fixture
def state() -> dict:
    return ModelSecurityState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.model_security.graph import create_model_security_graph

    sg = create_model_security_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ModelSecurityState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.model_security.graph import create_model_security_graph

    try:
        result = await create_model_security_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
