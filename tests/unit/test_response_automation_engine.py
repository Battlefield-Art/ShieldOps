"""Tests for response_automation_engine."""

from __future__ import annotations

from shieldops.agents.response_automation_engine.models import (
    AutomationLevel,
    RAEStage,
    ResponseAction,
    ResponseAutomationEngineState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RAEStage.DETECT_TRIGGER == "detect_trigger"
        assert len(RAEStage) >= 3

    def test_response_action(self) -> None:
        assert ResponseAction.ISOLATE_HOST == "isolate_host"
        assert len(ResponseAction) >= 3

    def test_automation_level(self) -> None:
        assert AutomationLevel.FULLY_AUTOMATED == "fully_automated"
        assert len(AutomationLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ResponseAutomationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ResponseAutomationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
