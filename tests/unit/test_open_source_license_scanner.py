"""Tests for open_source_license_scanner."""

from __future__ import annotations

from shieldops.agents.open_source_license_scanner.models import (
    ComplianceStatus,
    LicenseCategory,
    OpenSourceLicenseScannerState,
    ScanStage,
)


class TestEnums:
    def test_compliancestatus(self) -> None:
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert len(ComplianceStatus) >= 3

    def test_licensecategory(self) -> None:
        assert LicenseCategory.PERMISSIVE == "permissive"
        assert len(LicenseCategory) >= 3

    def test_scanstage(self) -> None:
        assert ScanStage.DISCOVER_DEPS == "discover_deps"
        assert len(ScanStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = OpenSourceLicenseScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = OpenSourceLicenseScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
