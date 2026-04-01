"""State models for the Compliance Drift Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class CDMStage(StrEnum):
    """Workflow stages for compliance drift monitoring."""

    LOAD_BASELINES = "load_baselines"
    SCAN_CURRENT_STATE = "scan_current_state"
    DETECT_DRIFT = "detect_drift"
    ASSESS_IMPACT = "assess_impact"
    PLAN_REMEDIATION = "plan_remediation"
    REPORT = "report"


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"
    FEDRAMP = "fedramp"


class DriftSeverity(StrEnum):
    """Severity of detected compliance drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Domain Models ─────────────────────────────────────


class BaselineRecord(BaseModel):
    """A compliance baseline configuration record."""

    baseline_id: str = ""
    framework: str = ""
    control_id: str = ""
    expected_value: str = ""
    category: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DriftFinding(BaseModel):
    """A detected drift from compliance baseline."""

    finding_id: str = ""
    control_id: str = ""
    framework: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    expected_value: str = ""
    actual_value: str = ""
    resource: str = ""
    description: str = ""


class RemediationPlan(BaseModel):
    """Remediation plan for a drift finding."""

    plan_id: str = ""
    finding_id: str = ""
    action: str = ""
    priority: str = ""
    estimated_effort_hours: float = 0.0
    automated: bool = False


class ImpactAssessment(BaseModel):
    """Impact assessment for detected drift."""

    total_drifts: int = 0
    critical_count: int = 0
    frameworks_affected: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the compliance drift workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ComplianceDriftMonitorState(BaseModel):
    """Full state for the Compliance Drift Monitor workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CDMStage = CDMStage.LOAD_BASELINES
    config: dict[str, Any] = Field(default_factory=dict)

    baselines: list[dict[str, Any]] = Field(default_factory=list)
    current_state: list[dict[str, Any]] = Field(default_factory=list)
    drift_findings: list[dict[str, Any]] = Field(default_factory=list)
    impact_assessments: list[dict[str, Any]] = Field(default_factory=list)
    remediation_plans: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
