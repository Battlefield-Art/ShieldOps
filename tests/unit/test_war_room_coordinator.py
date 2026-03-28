"""Unit tests for war_room_coordinator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.war_room_coordinator.models import (
    ActionItem,
    ActionStatus,
    CommunicationLog,
    RoleAssignment,
    TeamRole,
    TimelineEntry,
    WarRoom,
    WarRoomCoordinatorState,
    WarRoomStage,
)
from shieldops.agents.war_room_coordinator.tools import (
    ROLE_TEMPLATES,
    WarRoomCoordinatorToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_war_room_stage_values(self):
        assert WarRoomStage.OPEN_WAR_ROOM == "open_war_room"
        assert WarRoomStage.REPORT == "report"

    def test_team_role_values(self):
        assert TeamRole.INCIDENT_COMMANDER == "incident_commander"
        assert TeamRole.FORENSICS == "forensics"

    def test_action_status_values(self):
        assert ActionStatus.ASSIGNED == "assigned"
        assert ActionStatus.ESCALATED == "escalated"


class TestState:
    def test_defaults(self):
        state = WarRoomCoordinatorState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == WarRoomStage.OPEN_WAR_ROOM
        assert state.incident_id == ""
        assert state.incident_details == {}
        assert state.role_assignments == []
        assert state.action_items == []
        assert state.timeline == []
        assert state.comms_log == []
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = WarRoomCoordinatorState(
            request_id="req-1",
            tenant_id="t-1",
            incident_id="inc-42",
            incident_details={"title": "Server fire", "severity": "critical"},
        )
        assert state.request_id == "req-1"
        assert state.incident_id == "inc-42"
        assert state.incident_details["severity"] == "critical"


class TestModels:
    def test_war_room_defaults(self):
        wr = WarRoom()
        assert wr.id == ""
        assert wr.status == "active"
        assert wr.severity == "high"

    def test_role_assignment_defaults(self):
        ra = RoleAssignment()
        assert ra.role == TeamRole.TECHNICAL_LEAD
        assert ra.accepted is False

    def test_action_item_defaults(self):
        ai = ActionItem()
        assert ai.status == ActionStatus.ASSIGNED
        assert ai.priority == "high"

    def test_timeline_entry_defaults(self):
        te = TimelineEntry()
        assert te.event == ""

    def test_communication_log_defaults(self):
        cl = CommunicationLog()
        assert cl.message_type == "update"


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return WarRoomCoordinatorToolkit()

    @pytest.mark.asyncio
    async def test_open_war_room(self, toolkit):
        result = await toolkit.open_war_room(
            incident_id="inc-123",
            incident_details={"title": "Data breach", "severity": "critical"},
        )
        assert isinstance(result, WarRoom)
        assert result.id.startswith("wr-")
        assert result.incident_id == "inc-123"
        assert result.severity == "critical"
        assert result.status == "active"
        assert result.channel.startswith("#war-room-")

    @pytest.mark.asyncio
    async def test_open_war_room_default_severity(self, toolkit):
        result = await toolkit.open_war_room(
            incident_id="inc-456",
            incident_details={"title": "Minor issue"},
        )
        assert result.severity == "high"

    @pytest.mark.asyncio
    async def test_assign_roles_critical(self, toolkit):
        war_room = WarRoom(severity="critical")
        assignments = await toolkit.assign_roles(
            war_room=war_room,
            incident_details={},
        )
        expected_roles = ROLE_TEMPLATES["critical"]
        assert len(assignments) == len(expected_roles)
        for assignment in assignments:
            assert isinstance(assignment, RoleAssignment)
            assert assignment.id.startswith("ra-")

    @pytest.mark.asyncio
    async def test_assign_roles_low(self, toolkit):
        war_room = WarRoom(severity="low")
        assignments = await toolkit.assign_roles(
            war_room=war_room,
            incident_details={},
        )
        assert len(assignments) == 1
        assert assignments[0].role == TeamRole.TECHNICAL_LEAD

    @pytest.mark.asyncio
    async def test_generate_actions(self, toolkit):
        war_room = WarRoom()
        assignments = [
            RoleAssignment(
                role=TeamRole.INCIDENT_COMMANDER,
                assignee="ic-oncall",
            ),
            RoleAssignment(
                role=TeamRole.TECHNICAL_LEAD,
                assignee="tech-oncall",
            ),
        ]
        actions = await toolkit.generate_actions(
            war_room=war_room,
            role_assignments=assignments,
            incident_details={},
        )
        assert len(actions) > 0
        for action in actions:
            assert isinstance(action, ActionItem)
            assert action.id.startswith("act-")
            assert action.status == ActionStatus.ASSIGNED

    @pytest.mark.asyncio
    async def test_build_timeline(self, toolkit):
        war_room = WarRoom(opened_at=1000.0)
        actions = [
            ActionItem(title="Do thing", assignee="person", created_at=1001.0),
        ]
        timeline = await toolkit.build_timeline(
            war_room=war_room,
            actions=actions,
            incident_details={},
        )
        assert len(timeline) >= 2  # war room opened + at least one action
        assert timeline[0].event == "War room opened"
        for entry in timeline:
            assert isinstance(entry, TimelineEntry)

    @pytest.mark.asyncio
    async def test_send_comms(self, toolkit):
        war_room = WarRoom(channel="#test-channel")
        result = await toolkit.send_comms(
            war_room=war_room,
            message="Status update",
            audience="internal",
        )
        assert isinstance(result, CommunicationLog)
        assert result.channel == "#test-channel"
        assert result.message == "Status update"
        assert result.audience == "internal"
        assert result.id.startswith("comm-")


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_open_war_room_node(self):
        from shieldops.agents.war_room_coordinator.nodes import (
            open_war_room,
            set_toolkit,
        )

        set_toolkit(WarRoomCoordinatorToolkit())
        state = {
            "incident_id": "inc-1",
            "incident_details": {"title": "Test", "severity": "high"},
            "reasoning_chain": [],
        }
        result = await open_war_room(state)
        assert "war_room" in result
        assert isinstance(result["war_room"], WarRoom)
        assert result["stage"] == WarRoomStage.OPEN_WAR_ROOM

    @pytest.mark.asyncio
    async def test_assign_roles_node(self):
        from shieldops.agents.war_room_coordinator.nodes import (
            assign_roles,
            set_toolkit,
        )

        set_toolkit(WarRoomCoordinatorToolkit())
        state = {
            "war_room": WarRoom(severity="medium"),
            "incident_details": {"title": "Test"},
            "reasoning_chain": [],
        }
        result = await assign_roles(state)
        assert "role_assignments" in result
        assert len(result["role_assignments"]) > 0

    @pytest.mark.asyncio
    async def test_track_actions_node(self):
        from shieldops.agents.war_room_coordinator.nodes import (
            set_toolkit,
            track_actions,
        )

        set_toolkit(WarRoomCoordinatorToolkit())
        state = {
            "war_room": WarRoom(severity="high"),
            "role_assignments": [
                RoleAssignment(
                    role=TeamRole.TECHNICAL_LEAD,
                    assignee="eng",
                ),
            ],
            "incident_details": {},
            "reasoning_chain": [],
        }
        result = await track_actions(state)
        assert "action_items" in result
        assert len(result["action_items"]) > 0

    @pytest.mark.asyncio
    async def test_maintain_timeline_node(self):
        from shieldops.agents.war_room_coordinator.nodes import (
            maintain_timeline,
            set_toolkit,
        )

        set_toolkit(WarRoomCoordinatorToolkit())
        state = {
            "war_room": WarRoom(opened_at=1000.0),
            "action_items": [ActionItem(title="Fix it", created_at=1001.0)],
            "incident_details": {},
            "reasoning_chain": [],
        }
        result = await maintain_timeline(state)
        assert "timeline" in result
        assert len(result["timeline"]) >= 1

    @pytest.mark.asyncio
    async def test_report_node(self):
        from shieldops.agents.war_room_coordinator.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(WarRoomCoordinatorToolkit())
        state = {
            "war_room": WarRoom(),
            "role_assignments": [],
            "action_items": [],
            "timeline": [],
            "comms_log": [],
            "reasoning_chain": [],
            "session_start": 0.0,
        }
        result = await report(state)
        assert result["stage"] == WarRoomStage.REPORT
        assert "stats" in result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.war_room_coordinator.runner import (
            WarRoomCoordinatorRunner,
        )

        runner = WarRoomCoordinatorRunner()
        assert runner is not None
