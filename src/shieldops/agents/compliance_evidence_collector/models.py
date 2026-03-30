"""State models for the Compliance Evidence Collector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class EvidenceStage(StrEnum):
    """Workflow stages for compliance evidence collection."""

    IDENTIFY_CONTROLS = "identify_controls"
    COLLECT_EVIDENCE = "collect_evidence"
    VALIDATE = "validate"
    MAP_FRAMEWORKS = "map_frameworks"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class EvidenceStatus(StrEnum):
    """Status of evidence collection."""

    COLLECTED = "collected"
    VALIDATED = "validated"
    INSUFFICIENT = "insufficient"
    MISSING = "missing"
    EXPIRED = "expired"


class ComplianceFramework(StrEnum):
    """Compliance frameworks supported."""

    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    NIST_CSF = "nist_csf"
    FEDRAMP = "fedramp"


# -- Domain Models -----------------------------------------------------


class ControlRequirement(BaseModel):
    """A compliance control requirement."""

    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    category: str = ""
    title: str = ""
    description: str = ""
    evidence_types: list[str] = Field(default_factory=list)
    is_automated: bool = False
    frequency: str = "annual"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    """A collected evidence item."""

    evidence_id: str = ""
    control_id: str = ""
    evidence_type: str = ""
    source: str = ""
    collected_at: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    content_hash: str = ""
    file_path: str = ""
    size_bytes: int = 0
    description: str = ""


class ValidationResult(BaseModel):
    """Validation result for an evidence item."""

    evidence_id: str = ""
    is_valid: bool = True
    completeness: float = 0.0
    freshness_days: int = 0
    issues: list[str] = Field(default_factory=list)
    reasoning: str = ""


class FrameworkMapping(BaseModel):
    """Mapping between controls and framework requirements."""

    control_id: str = ""
    frameworks: list[str] = Field(default_factory=list)
    coverage_pct: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    cross_references: list[str] = Field(default_factory=list)


class ComplianceReportSection(BaseModel):
    """A section of the compliance report."""

    section_id: str = ""
    framework: str = ""
    controls_total: int = 0
    controls_met: int = 0
    evidence_items: int = 0
    gaps: list[str] = Field(default_factory=list)
    summary: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the evidence collection workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ComplianceEvidenceCollectorState(BaseModel):
    """Full state for the Compliance Evidence Collector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: EvidenceStage = EvidenceStage.IDENTIFY_CONTROLS
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Control identification
    control_requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_controls: int = 0

    # Evidence collection
    evidence_items: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    collected_count: int = 0

    # Validation
    validation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    valid_count: int = 0

    # Framework mapping
    framework_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    coverage_pct: float = 0.0

    # Report
    report_sections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
