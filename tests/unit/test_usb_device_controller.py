"""Unit tests for usb_device_controller."""

from __future__ import annotations

from shieldops.agents.usb_device_controller.models import (
    DeviceClassification,
    TransferRisk,
    USBDeviceControllerState,
)


class TestEnums:
    def test_deviceclassification(self) -> None:
        assert DeviceClassification.WHITELISTED == "whitelisted"
        assert len(DeviceClassification) >= 3

    def test_transferrisk(self) -> None:
        assert TransferRisk.CRITICAL == "critical"
        assert len(TransferRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = USBDeviceControllerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = USBDeviceControllerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
