"""Compliance Reporter Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReporterStage(StrEnum):
    SELECT_FRAMEWORK = "select_framework"
    COLLECT_EVIDENCE = "collect_evidence"
    ASSESS_CONTROLS = "assess_controls"
    GENERATE_REPORT = "generate_report"
    PACKAGE_ARTIFACTS = "package_artifacts"
    DELIVER = "deliver"


class ComplianceFramework(StrEnum):
    SOC2_TYPE2 = "soc2_type2"
    PCI_DSS_4 = "pci_dss_4"
    HIPAA = "hipaa"
    FEDRAMP_MODERATE = "fedramp_moderate"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    NIST_CSF = "nist_csf"


class ControlStatus(StrEnum):
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_EVIDENCE = "pending_evidence"


class EvidenceItem(BaseModel):
    """A collected evidence artifact for compliance verification."""

    id: str = ""
    control_id: str = ""
    framework: str = ""
    title: str = ""
    description: str = ""
    evidence_type: str = ""
    source: str = ""
    collected_at: float = 0.0
    artifact_path: str = ""
    hash_digest: str = ""
    verified: bool = False


class ControlAssessment(BaseModel):
    """Assessment result for a single compliance control."""

    id: str = ""
    control_id: str = ""
    framework: str = ""
    control_name: str = ""
    status: ControlStatus = ControlStatus.PENDING_EVIDENCE
    findings: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    assessor_notes: str = ""
    last_assessed: float = 0.0


class ComplianceReport(BaseModel):
    """Formal compliance report with scoring and executive summary."""

    id: str = ""
    framework: str = ""
    report_title: str = ""
    period_start: str = ""
    period_end: str = ""
    total_controls: int = 0
    compliant_count: int = 0
    partially_compliant_count: int = 0
    non_compliant_count: int = 0
    compliance_score: float = 0.0
    executive_summary: str = ""
    control_assessments: list[dict[str, Any]] = Field(default_factory=list)
    generated_at: float = 0.0


class ArtifactPackage(BaseModel):
    """Packaged evidence artifacts for audit delivery."""

    id: str = ""
    report_id: str = ""
    package_path: str = ""
    total_artifacts: int = 0
    total_size_mb: float = 0.0
    hash_digest: str = ""
    created_at: float = 0.0


class DeliveryResult(BaseModel):
    """Result of report delivery to a stakeholder."""

    id: str = ""
    report_id: str = ""
    recipient: str = ""
    delivery_method: str = ""
    delivered_at: float = 0.0
    success: bool = False


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent's chain of thought."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComplianceReporterState(BaseModel):
    """Main state for the Compliance Reporter agent graph."""

    request_id: str = ""
    stage: ReporterStage = ReporterStage.SELECT_FRAMEWORK
    framework: ComplianceFramework = ComplianceFramework.SOC2_TYPE2
    period_start: str = ""
    period_end: str = ""

    # Evidence and assessments
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    control_assessments: list[ControlAssessment] = Field(default_factory=list)

    # Report and packaging
    compliance_report: ComplianceReport | None = None
    artifact_package: ArtifactPackage | None = None
    delivery_results: list[DeliveryResult] = Field(default_factory=list)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: int = 0

    # Session tracking
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
