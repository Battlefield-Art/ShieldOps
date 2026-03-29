"""Tests for privacy_impact_assessor."""

from __future__ import annotations

from shieldops.agents.privacy_impact_assessor.models import (
    AssessmentStage,
    DataCategory,
    PrivacyImpactAssessorState,
    PrivacyRisk,
)


class TestEnums:
    def test_assessmentstage(self) -> None:
        assert AssessmentStage.IDENTIFY_PROCESSING == "identify_processing"
        assert len(AssessmentStage) >= 3

    def test_datacategory(self) -> None:
        assert DataCategory.PII == "pii"
        assert len(DataCategory) >= 3

    def test_privacyrisk(self) -> None:
        assert PrivacyRisk.HIGH == "high"
        assert len(PrivacyRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PrivacyImpactAssessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PrivacyImpactAssessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
