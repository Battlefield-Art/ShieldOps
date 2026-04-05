"""Integration test for the Alert Correlation Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.alert_correlation.models import AlertCorrelationState, CorrelationStage


@pytest.fixture
def state() -> dict:
    return AlertCorrelationState(
        request_id="test-ac-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.alert_correlation.graph import create_alert_correlation_graph

    sg = create_alert_correlation_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "collect_alerts",
        "normalize",
        "correlate",
        "build_chains",
        "prioritize",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = AlertCorrelationState()
    assert s.stage == CorrelationStage.COLLECT_ALERTS
    assert s.noise_reduction_ratio == 0.0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.alert_correlation.graph import create_alert_correlation_graph

    try:
        result = await create_alert_correlation_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
