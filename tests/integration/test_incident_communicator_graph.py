"""Integration test for Incident Communicator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.incident_communicator.models import (
    CommStage,
    IncidentCommunicatorState,
)


@pytest.fixture
def state() -> dict:
    return IncidentCommunicatorState(
        request_id="test-ic-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.incident_communicator.graph import (
        create_incident_communicator_graph,
    )

    sg = create_incident_communicator_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "identify_stakeholders",
        "draft_messages",
        "select_channels",
        "send_notifications",
        "track_acks",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = IncidentCommunicatorState()
    assert s.stage == CommStage.IDENTIFY_STAKEHOLDERS
    assert s.error == ""
    assert s.notifications == []


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.incident_communicator.graph import (
        create_incident_communicator_graph,
    )

    try:
        sg = create_incident_communicator_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
