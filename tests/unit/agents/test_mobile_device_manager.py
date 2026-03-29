"""Tests for shieldops.agents.mobile_device_manager."""

from __future__ import annotations

import pytest

from shieldops.agents.mobile_device_manager.models import (
    AppPolicy,
    ComplianceStatus,
    ComplianceViolation,
    DeviceAction,
    MDMStage,
    MobileDevice,
    MobileDeviceManagerState,
)


def _state(**kw) -> MobileDeviceManagerState:
    return MobileDeviceManagerState(**kw)


class TestEnums:
    def test_mdm_stage_values(self):
        assert MDMStage.DISCOVER_DEVICES == "discover_devices"
        assert MDMStage.CHECK_ENROLLMENT == "check_enrollment"
        assert MDMStage.ASSESS_COMPLIANCE == "assess_compliance"
        assert MDMStage.ENFORCE_POLICIES == "enforce_policies"
        assert MDMStage.CHECK_APPS == "check_apps"
        assert MDMStage.REPORT == "report"

    def test_compliance_status_values(self):
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert ComplianceStatus.NON_COMPLIANT == "non_compliant"
        assert ComplianceStatus.PARTIALLY_COMPLIANT == "partially_compliant"
        assert ComplianceStatus.PENDING == "pending"
        assert ComplianceStatus.UNENROLLED == "unenrolled"

    def test_device_action_values(self):
        assert DeviceAction.ENROLL == "enroll"
        assert DeviceAction.LOCK == "lock"
        assert DeviceAction.WIPE == "wipe"
        assert DeviceAction.RESTRICT == "restrict"
        assert DeviceAction.NOTIFY == "notify"
        assert DeviceAction.ALLOW == "allow"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == MDMStage.DISCOVER_DEVICES
        assert s.devices == []
        assert s.total_devices == 0
        assert s.unenrolled_count == 0
        assert s.violations == []
        assert s.compliant_count == 0
        assert s.non_compliant_count == 0
        assert s.blocked_apps == []
        assert s.actions_taken == []
        assert s.encryption_enforced == 0
        assert s.summary == ""
        assert s.compliance_rate == 0.0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(total_devices=50, compliance_rate=87.3)
        assert s.total_devices == 50
        assert s.compliance_rate == 87.3

    def test_mobile_device_defaults(self):
        d = MobileDevice()
        assert d.device_id == ""
        assert d.enrolled is False
        assert d.encrypted is False
        assert d.compliance == ComplianceStatus.PENDING

    def test_app_policy_defaults(self):
        a = AppPolicy()
        assert a.app_name == ""
        assert a.allowed is True
        assert a.required is False

    def test_compliance_violation_defaults(self):
        v = ComplianceViolation()
        assert v.device_id == ""
        assert v.rule == ""
        assert v.action_taken == DeviceAction.NOTIFY


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.mobile_device_manager.tools import (
            MobileDeviceManagerToolkit,
        )

        return MobileDeviceManagerToolkit()

    @pytest.mark.asyncio
    async def test_discover_devices(self, toolkit):
        result = await toolkit.discover_devices("t-01")
        assert isinstance(result, list)
        assert len(result) >= 3

    @pytest.mark.asyncio
    async def test_check_enrollment(self, toolkit):
        devices = await toolkit.discover_devices("t-01")
        count, unenrolled = await toolkit.check_enrollment(devices)
        assert isinstance(count, int)
        assert count >= 1

    @pytest.mark.asyncio
    async def test_assess_compliance(self, toolkit):
        devices = await toolkit.discover_devices("t-01")
        violations, compliant, non = await toolkit.assess_compliance(devices)
        assert isinstance(violations, list)
        assert compliant + non == len(devices)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.mobile_device_manager.graph import (
            create_mobile_device_manager_graph,
        )

        sg = create_mobile_device_manager_graph()
        assert sg.compile() is not None
