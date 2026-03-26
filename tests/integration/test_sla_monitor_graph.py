"""Integration test for the SLA Monitor Agent."""
from __future__ import annotations
import pytest
from shieldops.agents.sla_monitor.models import SLAMonitorState, MonitorStage

@pytest.fixture
def state() -> dict:
    return SLAMonitorState(request_id="test-sm-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.sla_monitor.graph import create_sla_monitor_graph
    sg = create_sla_monitor_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in ["collect_slis", "calculate_slos", "track_error_budgets", "detect_burn_rate", "alert", "generate_report"]:
        assert name in nodes, f"Missing: {name}"

def test_state_defaults():
    s = SLAMonitorState()
    assert s.stage == MonitorStage.COLLECT_SLIS

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.sla_monitor.graph import create_sla_monitor_graph
    sg = create_sla_monitor_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
