"""Tests for communication_auditor."""

from __future__ import annotations

from shieldops.agents.communication_auditor.models import (
    AuditStage,
    ChannelType,
    CommunicationAuditorState,
    ComplianceStatus,
)


class TestEnums:
    def test_auditstage(self) -> None:
        assert AuditStage.COLLECT_MESSAGES == "collect_messages"
        assert len(AuditStage) >= 3

    def test_channeltype(self) -> None:
        assert ChannelType.SLACK == "slack"
        assert len(ChannelType) >= 3

    def test_compliancestatus(self) -> None:
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert len(ComplianceStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CommunicationAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CommunicationAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
