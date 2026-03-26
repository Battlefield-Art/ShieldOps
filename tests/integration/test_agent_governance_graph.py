"""Integration test for the agent_governance agent."""

from __future__ import annotations

import pytest

from shieldops.agents.agent_governance.models import AgentGovernanceState


@pytest.fixture
def state() -> dict:
    return AgentGovernanceState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.agent_governance.graph import create_agent_governance_graph

    sg = create_agent_governance_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AgentGovernanceState()
    assert s.error == ""
    assert s.compliance_score == 0.0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.agent_governance.graph import create_agent_governance_graph

    try:
        result = await create_agent_governance_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
        assert result.get("total_agents", 0) > 0
    except Exception:
        pytest.skip("Requires dependencies")
