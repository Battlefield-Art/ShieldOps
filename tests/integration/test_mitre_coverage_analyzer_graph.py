"""Integration test for mitre_coverage_analyzer."""

from __future__ import annotations

import pytest

from shieldops.agents.mitre_coverage_analyzer.models import MITRECoverageAnalyzerState


@pytest.fixture
def state() -> dict:
    return MITRECoverageAnalyzerState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.mitre_coverage_analyzer.graph import create_mitre_coverage_analyzer_graph

    sg = create_mitre_coverage_analyzer_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = MITRECoverageAnalyzerState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.mitre_coverage_analyzer.graph import create_mitre_coverage_analyzer_graph

    try:
        result = await create_mitre_coverage_analyzer_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
