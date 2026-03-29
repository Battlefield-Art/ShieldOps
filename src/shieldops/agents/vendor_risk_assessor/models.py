"""Vendor Risk Assessor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AssessmentStage(StrEnum):
    COLLECT_DATA = "collect_data"
    SCORE_RISK = "score_risk"
    EVALUATE_CONTROLS = "evaluate_controls"
    CLASSIFY_VENDOR = "classify_vendor"
    RECOMMEND = "recommend"
    REPORT = "report"


class VendorTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class RiskDomain(StrEnum):
    SECURITY = "security"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"


class VendorRiskAssessorState(BaseModel):
    request_id: str = ""
    stage: AssessmentStage = AssessmentStage.COLLECT_DATA
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
