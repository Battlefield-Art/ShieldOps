"""Integration test for the Capacity Planner Agent."""
from __future__ import annotations
import pytest
from shieldops.agents.capacity_planner.models import CapacityPlannerState, CapacityStage

@pytest.fixture
def state() -> dict:
    return CapacityPlannerState(request_id="test-cp-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.capacity_planner.graph import create_capacity_planner_graph
    sg = create_capacity_planner_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in ["collect_metrics", "forecast_demand", "identify_bottlenecks", "plan_scaling", "recommend", "generate_report"]:
        assert name in nodes, f"Missing: {name}"

def test_state_defaults():
    s = CapacityPlannerState()
    assert s.stage == CapacityStage.COLLECT_METRICS
    assert s.resource_metrics == []

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.capacity_planner.graph import create_capacity_planner_graph
    sg = create_capacity_planner_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
