"""Tests for mfa_compliance_checker."""

from __future__ import annotations

from shieldops.agents.mfa_compliance_checker.models import (
    CheckStage,
    ComplianceLevel,
    MfaComplianceCheckerState,
    MFAMethod,
)


class TestEnums:
    def test_checkstage(self) -> None:
        assert CheckStage.DISCOVER_ACCOUNTS == "discover_accounts"
        assert len(CheckStage) >= 3

    def test_compliancelevel(self) -> None:
        assert ComplianceLevel.FULL == "full"
        assert len(ComplianceLevel) >= 3

    def test_mfamethod(self) -> None:
        assert MFAMethod.TOTP == "totp"
        assert len(MFAMethod) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = MfaComplianceCheckerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = MfaComplianceCheckerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
