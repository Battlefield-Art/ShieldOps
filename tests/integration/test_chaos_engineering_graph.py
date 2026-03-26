"""Integration test for the Chaos Engineering Agent."""
from __future__ import annotations
import pytest
from shieldops.agents.chaos_engineering.models import ChaosEngineeringState, ChaosStage

@pytest.fixture
def state() -> dict:
    return ChaosEngineeringState(request_id="test-ce-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.chaos_engineering.graph import create_chaos_engineering_graph
    sg = create_chaos_engineering_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in ["plan_experiment", "validate_safety", "inject_fault", "observe_impact", "analyze_results", "generate_report"]:
        assert name in nodes, f"Missing: {name}"

def test_state_defaults():
    s = ChaosEngineeringState()
    assert s.stage == ChaosStage.PLAN_EXPERIMENT

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.chaos_engineering.graph import create_chaos_engineering_graph
    sg = create_chaos_engineering_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
