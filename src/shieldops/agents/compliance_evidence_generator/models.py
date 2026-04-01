"""Compliance Evidence Generator — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------------------------


class CEGStage(StrEnum):
    """Workflow stages for compliance evidence generation."""

    IDENTIFY_CONTROLS = "identify_controls"
    COLLECT_EVIDENCE = "collect_evidence"
    VALIDATE_EVIDENCE = "validate_evidence"
    IDENTIFY_GAPS = "identify_gaps"
    PACKAGE_EVIDENCE = "package_evidence"
    GENERATE_REPORT = "generate_report"


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"


class EvidenceType(StrEnum):
    """Types of evidence artifacts."""

    CONFIGURATION_SNAPSHOT = "configuration_snapshot"
    LOG_EXPORT = "log_export"
    POLICY_DOCUMENT = "policy_document"
    TELEMETRY_REPORT = "telemetry_report"
    ACCESS_REVIEW = "access_review"
    SCAN_RESULT = "scan_result"


# -- Domain Models -------------------------------------------------------------


class ControlRequirement(BaseModel):
    """A single compliance control requirement."""

    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    title: str = ""
    description: str = ""
    category: str = ""
    required_evidence_types: list[EvidenceType] = Field(default_factory=list)
    criticality: str = "medium"


class EvidenceArtifact(BaseModel):
    """A collected evidence artifact supporting a control."""

    artifact_id: str = ""
    control_id: str = ""
    evidence_type: EvidenceType = EvidenceType.CONFIGURATION_SNAPSHOT
    source: str = ""
    description: str = ""
    collected_at: str = ""
    valid_until: str = ""
    hash_digest: str = ""
    content_ref: str = ""
    is_valid: bool = True


class ComplianceGap(BaseModel):
    """A gap identified during evidence validation."""

    gap_id: str = ""
    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    description: str = ""
    severity: str = "medium"
    remediation_suggestion: str = ""
    estimated_effort_hours: int = 0


class EvidencePackage(BaseModel):
    """A packaged set of evidence artifacts for audit submission."""

    package_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    controls_covered: int = 0
    artifacts_included: int = 0
    gaps_remaining: int = 0
    completeness_score: float = 0.0
    generated_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Final audit-ready compliance evidence report."""

    report_id: str = ""
    frameworks: list[str] = Field(default_factory=list)
    total_controls: int = 0
    evidence_collected: int = 0
    gaps_found: int = 0
    overall_completeness: float = 0.0
    packages: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: str = ""


# -- Reasoning + State ---------------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the evidence generation workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ComplianceEvidenceGeneratorState(BaseModel):
    """Full state for the Compliance Evidence Generator workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CEGStage = CEGStage.IDENTIFY_CONTROLS
    config: dict[str, Any] = Field(default_factory=dict)

    controls: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    validation_results: list[dict[str, Any]] = Field(default_factory=list)
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    packages: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
