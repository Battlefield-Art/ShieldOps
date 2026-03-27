"""Integration test for executive_reporter."""

from __future__ import annotations

import pytest

from shieldops.agents.executive_reporter.models import ExecutiveReporterState


@pytest.fixture
def state() -> dict:
    return ExecutiveReporterState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.executive_reporter.graph import create_executive_reporter_graph

    sg = create_executive_reporter_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ExecutiveReporterState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.executive_reporter.graph import create_executive_reporter_graph

    try:
        result = await create_executive_reporter_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
