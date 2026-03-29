"""Tests for shieldops.agents.usb_device_controller."""

from __future__ import annotations

import pytest

from shieldops.agents.usb_device_controller.models import (
    DataTransfer,
    DeviceClassification,
    TransferRisk,
    USBDevice,
    USBDeviceControllerState,
    USBPolicy,
    USBStage,
)


def _state(**kw) -> USBDeviceControllerState:
    return USBDeviceControllerState(**kw)


class TestEnums:
    def test_usb_stage_values(self):
        assert USBStage.SCAN_DEVICES == "scan_devices"
        assert USBStage.CHECK_WHITELIST == "check_whitelist"
        assert USBStage.MONITOR_TRANSFERS == "monitor_transfers"
        assert USBStage.ENFORCE_POLICY == "enforce_policy"
        assert USBStage.ASSESS_RISK == "assess_risk"
        assert USBStage.REPORT == "report"

    def test_device_classification_values(self):
        assert DeviceClassification.WHITELISTED == "whitelisted"
        assert DeviceClassification.UNAUTHORIZED == "unauthorized"
        assert DeviceClassification.PENDING_REVIEW == "pending_review"  # noqa: S105
        assert DeviceClassification.BLOCKED == "blocked"
        assert DeviceClassification.UNKNOWN == "unknown"

    def test_transfer_risk_values(self):
        assert TransferRisk.CRITICAL == "critical"
        assert TransferRisk.HIGH == "high"
        assert TransferRisk.MEDIUM == "medium"
        assert TransferRisk.LOW == "low"
        assert TransferRisk.NONE == "none"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == USBStage.SCAN_DEVICES
        assert s.connected_devices == []
        assert s.total_devices == 0
        assert s.unauthorized_devices == []
        assert s.whitelisted_count == 0
        assert s.unauthorized_count == 0
        assert s.transfers == []
        assert s.blocked_transfers == 0
        assert s.suspicious_transfers == 0
        assert s.enforcements == []
        assert s.policies_applied == 0
        assert s.risk_score == 0.0
        assert s.summary == ""
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(total_devices=10, unauthorized_count=3)
        assert s.total_devices == 10
        assert s.unauthorized_count == 3

    def test_usb_device_defaults(self):
        d = USBDevice()
        assert d.device_id == ""
        assert d.classification == DeviceClassification.UNKNOWN

    def test_data_transfer_defaults(self):
        t = DataTransfer()
        assert t.risk == TransferRisk.LOW
        assert t.blocked is False

    def test_usb_policy_defaults(self):
        p = USBPolicy()
        assert p.enabled is True


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.usb_device_controller.tools import (
            USBDeviceControllerToolkit,
        )

        return USBDeviceControllerToolkit()

    @pytest.mark.asyncio
    async def test_scan_devices(self, toolkit):
        result = await toolkit.scan_devices("t-01")
        assert isinstance(result, list)
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_check_whitelist(self, toolkit):
        devices = await toolkit.scan_devices("t-01")
        unauthorized, whitelisted, unauth = await toolkit.check_whitelist(devices)
        assert isinstance(unauthorized, list)
        assert whitelisted >= 1
        assert unauth >= 1

    @pytest.mark.asyncio
    async def test_monitor_transfers(self, toolkit):
        devices = await toolkit.scan_devices("t-01")
        await toolkit.check_whitelist(devices)
        transfers, blocked, suspicious = await toolkit.monitor_transfers(devices)
        assert isinstance(transfers, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.usb_device_controller.graph import (
            create_usb_device_controller_graph,
        )

        sg = create_usb_device_controller_graph()
        assert sg.compile() is not None
