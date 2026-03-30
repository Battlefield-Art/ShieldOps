"""Tests for on_call_optimizer."""

from __future__ import annotations

from shieldops.agents.on_call_optimizer.models import (
    BurnoutRisk,
    OCOStage,
    OnCallOptimizerState,
    ShiftType,
)


class TestEnums:
    def test_stage(self) -> None:
        assert OCOStage.ANALYZE_SCHEDULES == "analyze_schedules"
        assert len(OCOStage) >= 3

    def test_shift_type(self) -> None:
        assert ShiftType.PRIMARY == "primary"
        assert len(ShiftType) >= 3

    def test_burnout_risk(self) -> None:
        assert BurnoutRisk.CRITICAL == "critical"
        assert len(BurnoutRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = OnCallOptimizerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = OnCallOptimizerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
