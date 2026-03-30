"""Evidence Automation Engine Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EAEStage(StrEnum):
    IDENTIFY_REQUIREMENTS = "identify_requirements"
    COLLECT_EVIDENCE = "collect_evidence"
    VALIDATE_ARTIFACTS = "validate_artifacts"
    PACKAGE_EVIDENCE = "package_evidence"
    SUBMIT_ATTESTATION = "submit_attestation"
    REPORT = "report"


class EvidenceType(StrEnum):
    SCREENSHOT = "screenshot"
    LOG_EXPORT = "log_export"
    CONFIG_SNAPSHOT = "config_snapshot"
    API_RESPONSE = "api_response"
    SCAN_REPORT = "scan_report"
    POLICY_DOCUMENT = "policy_document"


class ValidationStatus(StrEnum):
    VERIFIED = "verified"
    PENDING = "pending"
    INCOMPLETE = "incomplete"
    EXPIRED = "expired"
    REJECTED = "rejected"


class EvidenceRequirement(BaseModel):
    """A single evidence requirement for compliance."""

    id: str = ""
    control_id: str = ""
    framework: str = ""
    description: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_EXPORT
    mandatory: bool = True


class EvidenceArtifact(BaseModel):
    """A collected evidence artifact."""

    id: str = ""
    requirement_id: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_EXPORT
    source: str = ""
    content_hash: str = ""
    collected_at: float = 0.0
    valid_until: float = 0.0
    status: ValidationStatus = ValidationStatus.PENDING


class AttestationRecord(BaseModel):
    """An attestation submission record."""

    id: str = ""
    framework: str = ""
    artifacts_count: int = 0
    submitted_at: float = 0.0
    accepted: bool = False


class EvidenceAutomationEngineState(BaseModel):
    """Main state for the Evidence Automation Engine."""

    request_id: str = ""
    tenant_id: str = ""
    stage: EAEStage = EAEStage.IDENTIFY_REQUIREMENTS

    # Pipeline data
    requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    artifacts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    attestations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_requirements: int = 0
    artifacts_collected: int = 0
    artifacts_verified: int = 0
    artifacts_rejected: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
