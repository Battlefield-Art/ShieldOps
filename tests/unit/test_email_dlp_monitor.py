"""Tests for email_dlp_monitor."""

from __future__ import annotations

from shieldops.agents.email_dlp_monitor.models import (
    DLPStage,
    EmailDLPMonitorState,
    PolicyAction,
    SensitiveDataType,
)


class TestEnums:
    def test_dlpstage(self) -> None:
        assert DLPStage.SCAN_OUTBOUND == "scan_outbound"
        assert len(DLPStage) >= 3

    def test_policyaction(self) -> None:
        assert PolicyAction.ALLOW == "allow"
        assert len(PolicyAction) >= 3

    def test_sensitivedatatype(self) -> None:
        assert SensitiveDataType.SSN == "ssn"
        assert len(SensitiveDataType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = EmailDLPMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = EmailDLPMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
