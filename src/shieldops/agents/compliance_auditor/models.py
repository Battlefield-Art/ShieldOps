"""Compliance Auditor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    SCAN = "scan"
    COLLECT_EVIDENCE = "collect_evidence"
    ANALYZE_GAPS = "analyze_gaps"
    GENERATE_REPORT = "generate_report"


class ComplianceFramework(StrEnum):
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO27001 = "iso27001"


class ControlStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


class ControlAssessment(BaseModel):
    """Assessment result for a single compliance control."""

    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    description: str = ""
    status: ControlStatus = ControlStatus.NOT_APPLICABLE
    evidence_refs: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    """A collected evidence artifact for compliance verification."""

    id: str = ""
    source: str = ""
    description: str = ""
    collected_at: float = 0.0
    valid_until: float = 0.0


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent's chain of thought."""

    step: str = ""
    detail: str = ""


class ComplianceAuditorState(BaseModel):
    """Main state for the Compliance Auditor agent graph."""

    request_id: str = ""
    stage: AuditStage = AuditStage.SCAN
    frameworks: list[ComplianceFramework] = Field(default_factory=list)

    # Assessments
    controls_assessed: list[ControlAssessment] = Field(default_factory=list)
    evidence_collected: list[EvidenceItem] = Field(default_factory=list)

    # Metrics
    gaps_found: int = 0
    compliance_score: float = 0.0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
