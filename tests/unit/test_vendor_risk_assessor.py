"""Tests for vendor_risk_assessor."""

from __future__ import annotations

from shieldops.agents.vendor_risk_assessor.models import (
    AssessmentStage,
    RiskDomain,
    VendorRiskAssessorState,
)


class TestEnums:
    def test_assessmentstage(self) -> None:
        assert AssessmentStage.COLLECT_DATA == "collect_data"
        assert len(AssessmentStage) >= 3

    def test_riskdomain(self) -> None:
        assert RiskDomain.SECURITY == "security"
        assert len(RiskDomain) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = VendorRiskAssessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = VendorRiskAssessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
