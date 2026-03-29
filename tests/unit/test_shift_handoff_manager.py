"""Tests for shift_handoff_manager."""

from __future__ import annotations

from shieldops.agents.shift_handoff_manager.models import (
    HandoffStage,
    HandoffStatus,
    ShiftHandoffManagerState,
    ShiftType,
)


class TestEnums:
    def test_handoffstage(self) -> None:
        assert HandoffStage.COLLECT_STATE == "collect_state"
        assert len(HandoffStage) >= 3

    def test_handoffstatus(self) -> None:
        assert HandoffStatus.PREPARING == "preparing"
        assert len(HandoffStatus) >= 3

    def test_shifttype(self) -> None:
        assert ShiftType.DAY == "day"
        assert len(ShiftType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ShiftHandoffManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ShiftHandoffManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
