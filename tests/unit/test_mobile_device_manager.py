"""Unit tests for mobile_device_manager."""

from __future__ import annotations

from shieldops.agents.mobile_device_manager.models import (
    ComplianceStatus,
    DeviceAction,
    MDMStage,
    MobileDeviceManagerState,
)


class TestEnums:
    def test_compliancestatus(self) -> None:
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert len(ComplianceStatus) >= 3

    def test_deviceaction(self) -> None:
        assert DeviceAction.ENROLL == "enroll"
        assert len(DeviceAction) >= 3

    def test_mdmstage(self) -> None:
        assert MDMStage.DISCOVER_DEVICES == "discover_devices"
        assert len(MDMStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = MobileDeviceManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = MobileDeviceManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
