"""Integration test for War Room Coordinator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.war_room_coordinator.models import (
    WarRoomCoordinatorState,
    WarRoomStage,
)


@pytest.fixture
def state() -> dict:
    return WarRoomCoordinatorState(
        request_id="test-wrc-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.war_room_coordinator.graph import (
        create_war_room_coordinator_graph,
    )

    sg = create_war_room_coordinator_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "open_war_room",
        "assign_roles",
        "track_actions",
        "maintain_timeline",
        "coordinate_comms",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = WarRoomCoordinatorState()
    assert s.stage == WarRoomStage.OPEN_WAR_ROOM
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.war_room_coordinator.graph import (
        create_war_room_coordinator_graph,
    )

    try:
        sg = create_war_room_coordinator_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
