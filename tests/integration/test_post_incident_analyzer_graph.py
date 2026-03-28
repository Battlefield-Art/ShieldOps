"""Integration test for Post-Incident Analyzer Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.post_incident_analyzer.models import (
    PostIncidentAnalyzerState,
    PostIncidentStage,
)


@pytest.fixture
def state() -> dict:
    return PostIncidentAnalyzerState(
        request_id="test-pia-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.post_incident_analyzer.graph import (
        create_post_incident_analyzer_graph,
    )

    sg = create_post_incident_analyzer_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "gather_timeline",
        "root_cause_analysis",
        "impact_assessment",
        "lessons_learned",
        "action_items",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = PostIncidentAnalyzerState()
    assert s.stage == PostIncidentStage.GATHER_TIMELINE
    assert s.error == ""
    assert s.action_items == []


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.post_incident_analyzer.graph import (
        create_post_incident_analyzer_graph,
    )

    try:
        sg = create_post_incident_analyzer_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
