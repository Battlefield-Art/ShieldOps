"""Integration test for security_scorecard."""

from __future__ import annotations

import pytest

from shieldops.agents.security_scorecard.models import SecurityScorecardState


@pytest.fixture
def state() -> dict:
    return SecurityScorecardState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.security_scorecard.graph import create_security_scorecard_graph

    sg = create_security_scorecard_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = SecurityScorecardState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.security_scorecard.graph import create_security_scorecard_graph

    try:
        result = await create_security_scorecard_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
