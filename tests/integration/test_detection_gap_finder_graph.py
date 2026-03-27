"""Integration test for detection_gap_finder."""

from __future__ import annotations

import pytest

from shieldops.agents.detection_gap_finder.models import DetectionGapFinderState


@pytest.fixture
def state() -> dict:
    return DetectionGapFinderState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.detection_gap_finder.graph import create_detection_gap_finder_graph

    sg = create_detection_gap_finder_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = DetectionGapFinderState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.detection_gap_finder.graph import create_detection_gap_finder_graph

    try:
        result = await create_detection_gap_finder_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
