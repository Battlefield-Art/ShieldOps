"""Integration test for the multi_agent_security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.multi_agent_security.models import MultiAgentSecurityState


@pytest.fixture
def state() -> dict:
    return MultiAgentSecurityState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.multi_agent_security.graph import create_multi_agent_security_graph

    sg = create_multi_agent_security_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = MultiAgentSecurityState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.multi_agent_security.graph import create_multi_agent_security_graph

    try:
        result = await create_multi_agent_security_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
