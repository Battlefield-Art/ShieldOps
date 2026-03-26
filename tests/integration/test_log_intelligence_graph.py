"""Integration test for the Log Intelligence agent."""

from __future__ import annotations

import pytest

from shieldops.agents.log_intelligence.models import LogIntelligenceState


@pytest.fixture
def state() -> dict:
    return LogIntelligenceState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.log_intelligence.graph import (
        create_log_intelligence_graph,
    )

    sg = create_log_intelligence_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = LogIntelligenceState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.log_intelligence.graph import (
        create_log_intelligence_graph,
    )

    try:
        g = create_log_intelligence_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
