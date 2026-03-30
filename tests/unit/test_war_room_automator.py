"""Tests for war_room_automator."""

from __future__ import annotations

from shieldops.agents.war_room_automator.models import (
    ParticipantRole,
    RoomType,
    WarRoomAutomatorState,
    WRAStage,
)


class TestEnums:
    def test_stage(self) -> None:
        assert WRAStage.DETECT_INCIDENT == "detect_incident"
        assert len(WRAStage) >= 3

    def test_room_type(self) -> None:
        assert RoomType.CRITICAL_INCIDENT == "critical_incident"
        assert len(RoomType) >= 3

    def test_participant_role(self) -> None:
        assert ParticipantRole.INCIDENT_COMMANDER == "incident_commander"
        assert len(ParticipantRole) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = WarRoomAutomatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = WarRoomAutomatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
