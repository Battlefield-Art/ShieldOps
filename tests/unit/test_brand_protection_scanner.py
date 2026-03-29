"""Tests for brand_protection_scanner."""

from __future__ import annotations

from shieldops.agents.brand_protection_scanner.models import (
    ActionStatus,
    BrandProtectionScannerState,
    ScanStage,
)


class TestEnums:
    def test_actionstatus(self) -> None:
        assert ActionStatus.DETECTED == "detected"
        assert len(ActionStatus) >= 3

    def test_scanstage(self) -> None:
        assert ScanStage.DISCOVER_DOMAINS == "discover_domains"
        assert len(ScanStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = BrandProtectionScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = BrandProtectionScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
