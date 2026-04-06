"""Compliance Auditor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    SCAN = "scan"
    CLOUDTRAIL_ANALYSIS = "cloudtrail_analysis"
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


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFinding(BaseModel):
    """A single compliance finding with framework mapping and remediation."""

    control_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    status: ControlStatus = ControlStatus.NON_COMPLIANT
    severity: FindingSeverity = FindingSeverity.MEDIUM
    title: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    remediation_hint: str = ""
    resource_id: str = ""
    check_type: str = ""
    assessed_at: str = ""


class CloudTrailEvent(BaseModel):
    """A parsed CloudTrail event relevant to compliance auditing."""

    event_id: str = ""
    event_name: str = ""
    event_source: str = ""
    event_time: str = ""
    username: str = ""
    source_ip: str = ""
    error_code: str = ""
    error_message: str = ""
    is_root_account: bool = False
    is_iam_change: bool = False
    is_unauthorized: bool = False
    raw_event: str = ""


class SecurityGroupFinding(BaseModel):
    """A finding from security group rule evaluation."""

    group_id: str = ""
    group_name: str = ""
    rule_direction: str = "ingress"
    protocol: str = ""
    port_range: str = ""
    cidr: str = ""
    is_open_to_world: bool = False
    risk_level: FindingSeverity = FindingSeverity.HIGH


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
    findings: list[ComplianceFinding] = Field(default_factory=list)

    # CloudTrail analysis
    cloudtrail_events: list[CloudTrailEvent] = Field(default_factory=list)
    security_group_findings: list[SecurityGroupFinding] = Field(default_factory=list)

    # Metrics
    gaps_found: int = 0
    compliance_score: float = 0.0

    # OPA policy evaluation
    policy_decision: str = ""
    policy_details: dict[str, Any] = Field(default_factory=dict)

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
