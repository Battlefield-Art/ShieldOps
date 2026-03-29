"""Tests for orphan_account_detector."""

from __future__ import annotations

from shieldops.agents.orphan_account_detector.models import (
    AccountType,
    DetectionStage,
    OrphanAccountDetectorState,
    OrphanReason,
)


class TestEnums:
    def test_accounttype(self) -> None:
        assert AccountType.USER == "user"
        assert len(AccountType) >= 3

    def test_detectionstage(self) -> None:
        assert DetectionStage.SCAN_ACCOUNTS == "scan_accounts"
        assert len(DetectionStage) >= 3

    def test_orphanreason(self) -> None:
        assert OrphanReason.DEPARTED_EMPLOYEE == "departed_employee"
        assert len(OrphanReason) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = OrphanAccountDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = OrphanAccountDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
