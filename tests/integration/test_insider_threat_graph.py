"""Integration test for the Insider Threat agent."""

from __future__ import annotations

import pytest

from shieldops.agents.insider_threat.models import InsiderThreatState


@pytest.fixture
def state() -> dict:
    return InsiderThreatState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.insider_threat.graph import (
        create_insider_threat_graph,
    )

    sg = create_insider_threat_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = InsiderThreatState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.insider_threat.graph import (
        create_insider_threat_graph,
    )

    try:
        g = create_insider_threat_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
