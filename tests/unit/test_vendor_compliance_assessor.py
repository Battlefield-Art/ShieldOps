"""Tests for vendor_compliance_assessor."""

from __future__ import annotations

from shieldops.agents.vendor_compliance_assessor.models import (
    ComplianceScore,
    VCAStage,
    VendorComplianceAssessorState,
    VendorTier,
)


class TestEnums:
    def test_stage(self) -> None:
        assert VCAStage.INVENTORY_VENDORS == "inventory_vendors"
        assert len(VCAStage) >= 3

    def test_vendor_tier(self) -> None:
        assert VendorTier.CRITICAL == "critical"
        assert len(VendorTier) >= 3

    def test_compliance_score(self) -> None:
        assert ComplianceScore.EXCELLENT == "excellent"
        assert len(ComplianceScore) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = VendorComplianceAssessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = VendorComplianceAssessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
