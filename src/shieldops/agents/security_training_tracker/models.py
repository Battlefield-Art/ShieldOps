"""State models for the Security Training Tracker Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class STTStage(StrEnum):
    """Stages in the security training tracking lifecycle."""

    ASSESS_REQUIREMENTS = "assess_requirements"
    TRACK_COMPLETION = "track_completion"
    MEASURE_EFFECTIVENESS = "measure_effectiveness"
    IDENTIFY_GAPS = "identify_gaps"
    REMEDIATE = "remediate"
    REPORT = "report"


class TrainingCategory(StrEnum):
    """Categories of security training."""

    PHISHING_AWARENESS = "phishing_awareness"
    SECURE_CODING = "secure_coding"
    INCIDENT_RESPONSE = "incident_response"
    DATA_HANDLING = "data_handling"
    COMPLIANCE = "compliance"
    ROLE_BASED = "role_based"


class CompletionStatus(StrEnum):
    """Training completion status."""

    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    OVERDUE = "overdue"
    NOT_STARTED = "not_started"
    EXEMPT = "exempt"
    FAILED = "failed"


# --- Domain models ---


class TrainingRequirement(BaseModel):
    """A security training requirement for an org unit."""

    requirement_id: str = ""
    category: TrainingCategory = TrainingCategory.PHISHING_AWARENESS
    title: str = ""
    mandatory: bool = True
    frequency_days: int = 365
    target_audience: str = ""
    compliance_framework: str = ""


class CompletionRecord(BaseModel):
    """A training completion record for an individual."""

    record_id: str = ""
    user_id: str = ""
    requirement_id: str = ""
    status: CompletionStatus = CompletionStatus.NOT_STARTED
    score: float = 0.0
    completed_at: datetime | None = None
    expires_at: datetime | None = None


class EffectivenessMetric(BaseModel):
    """Effectiveness measurement for a training program."""

    metric_id: str = ""
    category: TrainingCategory = TrainingCategory.PHISHING_AWARENESS
    phishing_click_rate: float = 0.0
    incident_reduction_pct: float = 0.0
    knowledge_score: float = 0.0
    behavior_change_score: float = 0.0


class TrainingGap(BaseModel):
    """An identified gap in training coverage."""

    gap_id: str = ""
    category: TrainingCategory = TrainingCategory.PHISHING_AWARENESS
    affected_users: int = 0
    risk_level: str = "medium"
    compliance_impact: str = ""
    recommendation: str = ""


class RemediationAction(BaseModel):
    """A remediation action for training gaps."""

    action_id: str = ""
    gap_id: str = ""
    action_type: str = ""
    assigned_to: str = ""
    due_date: datetime | None = None
    status: str = "pending"


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the tracker workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityTrainingTrackerState(BaseModel):
    """Full state for a security training tracker run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: STTStage = STTStage.ASSESS_REQUIREMENTS

    # Inputs
    org_units: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(
        default_factory=list,
    )

    # Pipeline fields
    requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    completions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    effectiveness: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_requirements: int = 0
    completion_rate: float = 0.0
    overdue_count: int = 0
    gap_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
