"""Compliance Drift Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CDMStage(StrEnum):
    SCAN_CONTROLS = "scan_controls"
    COMPARE_BASELINE = "compare_baseline"
    DETECT_DRIFT = "detect_drift"
    ASSESS_IMPACT = "assess_impact"
    ALERT = "alert"
    REPORT = "report"


class ControlStatus(StrEnum):
    COMPLIANT = "compliant"
    DRIFTED = "drifted"
    MISSING = "missing"
    PARTIALLY_COMPLIANT = "partially_compliant"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class DriftSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class ControlScan(BaseModel):
    """A scanned compliance control."""

    id: str = ""
    control_id: str = ""
    framework: str = ""
    description: str = ""
    status: ControlStatus = ControlStatus.COMPLIANT
    evidence: list[str] = Field(default_factory=list)
    last_checked: str = ""


class BaselineComparison(BaseModel):
    """Comparison of current state against baseline."""

    id: str = ""
    control_id: str = ""
    baseline_status: ControlStatus = ControlStatus.COMPLIANT
    current_status: ControlStatus = ControlStatus.COMPLIANT
    has_drifted: bool = False
    drift_detail: str = ""


class DriftEvent(BaseModel):
    """A detected compliance drift event."""

    id: str = ""
    control_id: str = ""
    framework: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    drift_type: str = ""
    description: str = ""
    detected_at: str = ""
    remediation_hint: str = ""


class ImpactAssessment(BaseModel):
    """Impact assessment of a compliance drift."""

    id: str = ""
    drift_event_id: str = ""
    business_impact: str = "medium"
    regulatory_risk: float = 0.0
    audit_readiness_impact: float = 0.0
    affected_assets: list[str] = Field(default_factory=list)
    priority: int = 3


class AlertRecord(BaseModel):
    """An alert sent for compliance drift."""

    id: str = ""
    drift_event_id: str = ""
    channel: str = ""
    recipients: list[str] = Field(default_factory=list)
    sent: bool = False
    acknowledged: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComplianceDriftMonitorState(BaseModel):
    """Main state for the Compliance Drift Monitor agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CDMStage = CDMStage.SCAN_CONTROLS

    controls: list[dict[str, Any]] = Field(default_factory=list)
    comparisons: list[dict[str, Any]] = Field(default_factory=list)
    drift_events: list[dict[str, Any]] = Field(default_factory=list)
    impact_assessments: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    report: str = ""
    total_controls_scanned: int = 0
    drifts_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
