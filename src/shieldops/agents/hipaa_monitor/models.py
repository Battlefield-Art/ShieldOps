"""HIPAA Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HIPAAStage(StrEnum):
    AUDIT_ACCESS = "audit_access"
    MINIMUM_NECESSARY = "minimum_necessary"
    BAA_CHECK = "baa_check"
    SECURITY_RULE = "security_rule"
    GENERATE_REPORT = "generate_report"


class PHICategory(StrEnum):
    DEMOGRAPHIC = "demographic"
    MEDICAL_RECORD = "medical_record"
    INSURANCE = "insurance"
    BILLING = "billing"
    GENETIC = "genetic"
    PSYCHOTHERAPY = "psychotherapy"


class ComplianceControl(StrEnum):
    ACCESS_CONTROL = "access_control"
    AUDIT_LOGGING = "audit_logging"
    INTEGRITY = "integrity"
    AUTHENTICATION = "authentication"  # noqa: S105
    TRANSMISSION_SECURITY = "transmission_security"
    ENCRYPTION = "encryption"


class PHIAccessLog(BaseModel):
    """Record of PHI access for audit purposes."""

    log_id: str = ""
    user_id: str = ""
    patient_id: str = ""
    phi_category: PHICategory = PHICategory.MEDICAL_RECORD
    action: str = "view"
    timestamp: str = ""
    justified: bool = True
    minimum_necessary: bool = True
    source_system: str = ""


class SecurityControl(BaseModel):
    """HIPAA Security Rule control assessment."""

    control_id: str = ""
    control_type: ComplianceControl = ComplianceControl.ACCESS_CONTROL
    description: str = ""
    status: str = "compliant"
    evidence_refs: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    cfr_reference: str = ""


class HIPAAMonitorState(BaseModel):
    """Main state for the HIPAA Monitor agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: HIPAAStage = HIPAAStage.AUDIT_ACCESS

    # Pipeline fields
    access_logs: list[dict[str, Any]] = Field(default_factory=list)
    minimum_necessary_violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    baa_records: list[dict[str, Any]] = Field(default_factory=list)
    security_controls: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    violations_found: int = 0
    compliance_score: float = 0.0
    phi_accesses_audited: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
