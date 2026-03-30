"""Tests for stakeholder_notifier."""

from __future__ import annotations

from shieldops.agents.stakeholder_notifier.models import (
    NotificationPriority,
    SNStage,
    StakeholderGroup,
    StakeholderNotifierState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert SNStage.IDENTIFY_STAKEHOLDERS == "identify_stakeholders"
        assert len(SNStage) >= 3

    def test_stakeholder_group(self) -> None:
        assert StakeholderGroup.ENGINEERING == "engineering"
        assert len(StakeholderGroup) >= 3

    def test_notification_priority(self) -> None:
        assert NotificationPriority.CRITICAL == "critical"
        assert len(NotificationPriority) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = StakeholderNotifierState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = StakeholderNotifierState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
