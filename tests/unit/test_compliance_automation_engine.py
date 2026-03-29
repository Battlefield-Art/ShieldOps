"""Tests for compliance_automation_engine."""

from __future__ import annotations

from shieldops.agents.compliance_automation_engine.models import (
    ComplianceAutomationEngineState,
    ComplianceFramework,
    ComplianceStage,
    ControlStatus,
)


class TestEnums:
    def test_compliance_stage(self) -> None:
        assert ComplianceStage.DISCOVER_CONTROLS == "discover_controls"
        assert len(ComplianceStage) >= 3

    def test_compliance_framework(self) -> None:
        assert ComplianceFramework.SOC2 == "soc2"
        assert len(ComplianceFramework) >= 3

    def test_control_status(self) -> None:
        assert ControlStatus.PASSING == "passing"
        assert len(ControlStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ComplianceAutomationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ComplianceAutomationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
