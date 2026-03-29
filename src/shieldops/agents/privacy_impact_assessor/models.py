"""Privacy Impact Assessor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AssessmentStage(StrEnum):
    IDENTIFY_PROCESSING = "identify_processing"
    MAP_DATA_FLOWS = "map_data_flows"
    ASSESS_RISKS = "assess_risks"
    IDENTIFY_MITIGATIONS = "identify_mitigations"
    DOCUMENT = "document"
    REPORT = "report"


class PrivacyRisk(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    MITIGATED = "mitigated"


class DataCategory(StrEnum):
    PII = "pii"
    PHI = "phi"
    FINANCIAL = "financial"
    BIOMETRIC = "biometric"
    BEHAVIORAL = "behavioral"
    SENSITIVE_PERSONAL = "sensitive_personal"


class PrivacyImpactAssessorState(BaseModel):
    request_id: str = ""
    stage: AssessmentStage = AssessmentStage.IDENTIFY_PROCESSING
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
