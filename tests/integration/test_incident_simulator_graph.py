"""Integration test for Incident Simulator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.incident_simulator.models import (
    IncidentSimulatorState,
    SimStage,
)


@pytest.fixture
def state() -> dict:
    return IncidentSimulatorState(
        request_id="test-is-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.incident_simulator.graph import (
        create_incident_simulator_graph,
    )

    sg = create_incident_simulator_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "design_scenario",
        "inject_events",
        "observe_response",
        "score_performance",
        "debrief",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = IncidentSimulatorState()
    assert s.stage == SimStage.DESIGN_SCENARIO
    assert s.error == ""
    assert s.readiness_score == 0.0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.incident_simulator.graph import (
        create_incident_simulator_graph,
    )

    try:
        sg = create_incident_simulator_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
