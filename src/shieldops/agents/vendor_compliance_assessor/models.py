"""Vendor Compliance Assessor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VCAStage(StrEnum):
    INVENTORY_VENDORS = "inventory_vendors"
    COLLECT_QUESTIONNAIRES = "collect_questionnaires"
    ASSESS_RISK = "assess_risk"
    SCORE_COMPLIANCE = "score_compliance"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class VendorTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ComplianceScore(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    FAILING = "failing"


class VendorRecord(BaseModel):
    """A vendor in the inventory."""

    id: str = ""
    name: str = ""
    tier: VendorTier = VendorTier.MEDIUM
    category: str = ""
    data_access: bool = False
    contract_expiry: str = ""
    last_assessed: str = ""


class QuestionnaireResponse(BaseModel):
    """A vendor questionnaire response."""

    vendor_id: str = ""
    question_id: str = ""
    question: str = ""
    answer: str = ""
    compliant: bool = True


class VendorRiskAssessment(BaseModel):
    """Risk assessment for a vendor."""

    vendor_id: str = ""
    vendor_name: str = ""
    tier: VendorTier = VendorTier.MEDIUM
    score: ComplianceScore = ComplianceScore.ACCEPTABLE
    risk_factors: list[str] = Field(default_factory=list)
    score_value: float = 0.0


class VendorComplianceAssessorState(BaseModel):
    """Main state for the Vendor Compliance Assessor."""

    request_id: str = ""
    tenant_id: str = ""
    stage: VCAStage = VCAStage.INVENTORY_VENDORS

    # Pipeline data
    vendors: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    questionnaires: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_vendors: int = 0
    critical_vendors: int = 0
    failing_vendors: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
