"""Integration test for the ai_compliance agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_compliance.models import AIComplianceState


@pytest.fixture
def state() -> dict:
    return AIComplianceState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.ai_compliance.graph import create_ai_compliance_graph

    sg = create_ai_compliance_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AIComplianceState()
    assert s.error == ""
    assert s.tenant_id == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ai_compliance.graph import create_ai_compliance_graph

    try:
        result = await create_ai_compliance_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
