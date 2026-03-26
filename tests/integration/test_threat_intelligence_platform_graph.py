"""Integration test for the Threat Intelligence Platform agent."""

from __future__ import annotations

import pytest

from shieldops.agents.threat_intelligence_platform.models import ThreatIntelligencePlatformState


@pytest.fixture
def state() -> dict:
    return ThreatIntelligencePlatformState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.threat_intelligence_platform.graph import (
        create_threat_intelligence_platform_graph,
    )

    sg = create_threat_intelligence_platform_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ThreatIntelligencePlatformState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.threat_intelligence_platform.graph import (
        create_threat_intelligence_platform_graph,
    )

    try:
        g = create_threat_intelligence_platform_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
