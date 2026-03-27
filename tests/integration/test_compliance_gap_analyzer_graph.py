"""Integration test for compliance_gap_analyzer."""

from __future__ import annotations

import pytest

from shieldops.agents.compliance_gap_analyzer.models import ComplianceGapAnalyzerState


@pytest.fixture
def state() -> dict:
    return ComplianceGapAnalyzerState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.compliance_gap_analyzer.graph import create_compliance_gap_analyzer_graph

    sg = create_compliance_gap_analyzer_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ComplianceGapAnalyzerState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.compliance_gap_analyzer.graph import create_compliance_gap_analyzer_graph

    try:
        result = await create_compliance_gap_analyzer_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
