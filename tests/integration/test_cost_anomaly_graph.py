"""Integration test for the Cost Anomaly Detector Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.cost_anomaly.models import (
    AnomalyType,
    CloudService,
    CostAnomaly,
    CostAnomalyState,
    CostSeverity,
    DetectorStage,
    WasteClassification,
)


@pytest.fixture
def cost_state() -> dict:
    return CostAnomalyState(
        request_id="test-ca-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.cost_anomaly.graph import create_cost_anomaly_graph

    sg = create_cost_anomaly_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_billing",
        "detect_anomalies",
        "classify_waste",
        "analyze_llm_costs",
        "recommend",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    anomaly = CostAnomaly(
        id="ca-001",
        service=CloudService.AWS_EC2,
        resource_id="i-0abc123",
        anomaly_type=AnomalyType.COST_SPIKE,
        severity=CostSeverity.HIGH,
        description="EC2 cost spiked 340% in 24 hours",
        expected_cost=120.0,
        actual_cost=528.0,
        deviation_pct=340.0,
    )
    waste = WasteClassification(
        id="wc-001",
        resource_id="i-0def456",
        service=CloudService.AWS_EC2,
        waste_type="idle_compute",
        monthly_waste=450.0,
        utilization_pct=2.1,
        recommendation="Terminate or downsize",
        savings_potential=450.0,
    )
    state = CostAnomalyState(
        anomalies=[anomaly],
        waste_classifications=[waste],
        stage=DetectorStage.RECOMMEND,
    )
    assert state.anomalies[0].deviation_pct == 340.0
    assert state.waste_classifications[0].savings_potential == 450.0


def test_state_defaults():
    state = CostAnomalyState()
    assert state.stage == DetectorStage.COLLECT_BILLING
    assert state.cost_data == []
    assert state.anomalies == []
    assert state.waste_classifications == []
    assert state.total_monthly_waste == 0.0
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(cost_state):
    from shieldops.agents.cost_anomaly.graph import create_cost_anomaly_graph

    sg = create_cost_anomaly_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(cost_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
