"""Tests for hipaa_monitor."""

from __future__ import annotations

from shieldops.agents.hipaa_monitor.models import (
    ComplianceControl,
    HIPAAMonitorState,
    HIPAAStage,
    PHICategory,
)


class TestEnums:
    def test_compliancecontrol(self) -> None:
        assert ComplianceControl.ACCESS_CONTROL == "access_control"
        assert len(ComplianceControl) >= 3

    def test_hipaastage(self) -> None:
        assert HIPAAStage.AUDIT_ACCESS == "audit_access"
        assert len(HIPAAStage) >= 3

    def test_phicategory(self) -> None:
        assert PHICategory.DEMOGRAPHIC == "demographic"
        assert len(PHICategory) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = HIPAAMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = HIPAAMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
