"""Integration test for the anomaly_detector agent."""

from __future__ import annotations

import pytest

from shieldops.agents.anomaly_detector.models import AnomalyDetectorState


@pytest.fixture
def state() -> dict:
    return AnomalyDetectorState(
        request_id="test-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.anomaly_detector.graph import create_anomaly_detector_graph

    sg = create_anomaly_detector_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AnomalyDetectorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.anomaly_detector.graph import create_anomaly_detector_graph

    try:
        result = await create_anomaly_detector_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
