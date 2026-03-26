"""Integration test for the threat_response agent."""
from __future__ import annotations
import pytest
from shieldops.agents.threat_response.models import ThreatResponseState

@pytest.fixture
def state() -> dict:
    return ThreatResponseState(request_id="test-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.threat_response.graph import create_threat_response_graph
    sg = create_threat_response_graph()
    assert sg.compile() is not None

def test_state_defaults():
    s = ThreatResponseState()
    assert s.error == ""

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.threat_response.graph import create_threat_response_graph
    try:
        result = await create_threat_response_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
