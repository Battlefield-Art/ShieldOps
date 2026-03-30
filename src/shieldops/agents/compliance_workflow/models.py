"""Compliance Workflow Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CWStage(StrEnum):
    """Stages of the compliance workflow pipeline."""

    IDENTIFY_FRAMEWORKS = "identify_frameworks"
    MAP_CONTROLS = "map_controls"
    COLLECT_EVIDENCE = "collect_evidence"
    ASSESS_GAPS = "assess_gaps"
    GENERATE_REMEDIATION = "generate_remediation"
    REPORT = "report"


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    NIST_CSF = "nist_csf"
    FEDRAMP = "fedramp"


class ControlStatus(StrEnum):
    """Assessment status for a compliance control."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"


class FrameworkMapping(BaseModel):
    """Maps a tenant to applicable compliance frameworks."""

    framework: ComplianceFramework = ComplianceFramework.SOC2
    applicable: bool = True
    reason: str = ""
    control_count: int = 0
    priority: int = 1


class ComplianceControl(BaseModel):
    """A single compliance control within a framework."""

    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    title: str = ""
    description: str = ""
    category: str = ""
    status: ControlStatus = ControlStatus.PENDING
    evidence_required: list[str] = Field(
        default_factory=list,
    )


class EvidenceItem(BaseModel):
    """An evidence artifact for control verification."""

    evidence_id: str = ""
    control_id: str = ""
    source: str = ""
    description: str = ""
    collected_at: float = 0.0
    valid: bool = False
    content_hash: str = ""


class ComplianceGap(BaseModel):
    """A gap identified during compliance assessment."""

    gap_id: str = ""
    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    severity: str = "medium"
    description: str = ""
    root_cause: str = ""
    risk_score: float = 0.0


class RemediationAction(BaseModel):
    """A remediation action to close a compliance gap."""

    action_id: str = ""
    gap_id: str = ""
    control_id: str = ""
    title: str = ""
    description: str = ""
    effort: str = "medium"
    priority: int = 1
    estimated_days: int = 0
    owner: str = ""


class ReasoningStep(BaseModel):
    """A single reasoning step in agent chain of thought."""

    step: str = ""
    detail: str = ""


class ComplianceWorkflowState(BaseModel):
    """Main state for the Compliance Workflow agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CWStage = CWStage.IDENTIFY_FRAMEWORKS

    # Pipeline data
    framework_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    controls: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediation_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    compliance_score: float = 0.0
    total_controls: int = 0
    gaps_found: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
