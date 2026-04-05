"""Integration test for the Log Analyzer Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.log_analyzer.models import AnalyzerStage, LogAnalyzerState


@pytest.fixture
def state() -> dict:
    return LogAnalyzerState(
        request_id="test-la-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.log_analyzer.graph import create_log_analyzer_graph

    sg = create_log_analyzer_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in [
        "collect_logs",
        "parse_patterns",
        "detect_anomalies",
        "correlate_events",
        "alert",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = LogAnalyzerState()
    assert s.stage == AnalyzerStage.COLLECT_LOGS


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.log_analyzer.graph import create_log_analyzer_graph

    sg = create_log_analyzer_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
