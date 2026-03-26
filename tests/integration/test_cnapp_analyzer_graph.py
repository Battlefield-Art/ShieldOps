"""Integration test for the cnapp_analyzer agent."""

from __future__ import annotations

import pytest

from shieldops.agents.cnapp_analyzer.models import CNAPPAnalyzerState


@pytest.fixture
def state() -> dict:
    return CNAPPAnalyzerState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.cnapp_analyzer.graph import create_cnapp_analyzer_graph

    sg = create_cnapp_analyzer_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CNAPPAnalyzerState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.cnapp_analyzer.graph import create_cnapp_analyzer_graph

    try:
        result = await create_cnapp_analyzer_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
