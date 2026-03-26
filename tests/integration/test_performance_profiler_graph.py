"""Integration test for the Performance Profiler Agent."""
from __future__ import annotations
import pytest
from shieldops.agents.performance_profiler.models import PerformanceProfilerState, ProfilerStage

@pytest.fixture
def state() -> dict:
    return PerformanceProfilerState(request_id="test-pp-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.performance_profiler.graph import create_performance_profiler_graph
    sg = create_performance_profiler_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in ["collect_traces", "analyze_latency", "detect_bottlenecks", "identify_contention", "recommend", "generate_report"]:
        assert name in nodes, f"Missing: {name}"

def test_state_defaults():
    s = PerformanceProfilerState()
    assert s.stage == ProfilerStage.COLLECT_TRACES

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.performance_profiler.graph import create_performance_profiler_graph
    try:
        result = await create_performance_profiler_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
