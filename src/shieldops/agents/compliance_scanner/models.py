"""Compliance Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    SELECT_FRAMEWORKS = "select_frameworks"
    SCAN_CONTROLS = "scan_controls"
    EVALUATE_FINDINGS = "evaluate_findings"
    TRACK_REMEDIATION = "track_remediation"
    GENERATE_EVIDENCE = "generate_evidence"
    REPORT = "report"


class ControlStatus(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceControl(BaseModel):
    """A compliance control from a framework."""

    id: str = ""
    framework: str = ""
    control_id: str = ""
    control_name: str = ""
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    evidence_type: str = ""
    last_scanned: datetime | None = None
    description: str = ""
    category: str = ""


class ScanFinding(BaseModel):
    """A finding from compliance scanning."""

    id: str = ""
    control_id: str = ""
    finding_type: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    auto_remediable: bool = False
    resource: str = ""
    recommendation: str = ""


class RemediationTracker(BaseModel):
    """Tracks remediation of a compliance finding."""

    finding_id: str = ""
    status: str = "open"
    assignee: str = ""
    due_date: datetime | None = None
    action_taken: str = ""


class EvidenceArtifact(BaseModel):
    """A compliance evidence artifact."""

    control_id: str = ""
    artifact_type: str = ""
    description: str = ""
    collected_at: datetime | None = None
    storage_path: str = ""
    hash_value: str = ""


class ComplianceScannerState(BaseModel):
    """Main state for the Compliance Scanner agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    frameworks: list[str] = Field(default_factory=list)
    stage: ComplianceStage = ComplianceStage.SELECT_FRAMEWORKS

    # Controls
    controls: list[dict[str, Any]] = Field(default_factory=list)

    # Findings
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Remediation tracking
    remediations: list[dict[str, Any]] = Field(default_factory=list)

    # Evidence
    evidence: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_controls: int = 0
    pass_count: int = 0
    fail_count: int = 0
    compliance_score: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
