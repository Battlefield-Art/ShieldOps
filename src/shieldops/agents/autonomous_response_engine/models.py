"""State models for the Autonomous Response Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class AREStage(StrEnum):
    """Stages in the autonomous response lifecycle."""

    DETECT_INCIDENT = "detect_incident"
    CLASSIFY_SEVERITY = "classify_severity"
    SELECT_PLAYBOOK = "select_playbook"
    EXECUTE_RESPONSE = "execute_response"
    VALIDATE_OUTCOME = "validate_outcome"
    REPORT = "report"


class IncidentSeverity(StrEnum):
    """Incident severity classifications."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ResponseAction(StrEnum):
    """Types of automated response actions."""

    ISOLATE = "isolate"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REVOKE_ACCESS = "revoke_access"
    PATCH = "patch"
    ROLLBACK = "rollback"


# --- Domain models ---


class IncidentDetection(BaseModel):
    """A detected security incident."""

    incident_id: str = ""
    source: str = ""
    alert_type: str = ""
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    detection_time: datetime | None = None
    confidence: float = 0.0


class SeverityClassification(BaseModel):
    """Severity classification for an incident."""

    classification_id: str = ""
    incident_id: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    business_impact: str = "moderate"
    data_at_risk: bool = False
    lateral_movement: bool = False
    confidence: float = 0.0
    rationale: str = ""


class PlaybookSelection(BaseModel):
    """Selected playbook for incident response."""

    playbook_id: str = ""
    playbook_name: str = ""
    response_actions: list[ResponseAction] = Field(
        default_factory=list,
    )
    estimated_time_minutes: int = 0
    requires_approval: bool = False
    rollback_available: bool = True


class ResponseExecution(BaseModel):
    """Execution result for a response action."""

    execution_id: str = ""
    action: ResponseAction = ResponseAction.ISOLATE
    target: str = ""
    status: str = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    success: bool = False
    output: str = ""


class OutcomeValidation(BaseModel):
    """Validation of response outcome."""

    validation_id: str = ""
    incident_id: str = ""
    threat_contained: bool = False
    services_restored: bool = False
    false_positive: bool = False
    residual_risk: float = 0.0
    validation_checks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the response engine workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousResponseEngineState(BaseModel):
    """Full state for an autonomous response engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: AREStage = AREStage.DETECT_INCIDENT

    # Inputs
    incident_name: str = ""
    alert_source: str = ""
    alert_data: dict[str, Any] = Field(default_factory=dict)
    auto_execute: bool = True

    # Pipeline fields
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    selected_playbook: dict[str, Any] = Field(
        default_factory=dict,
    )
    executions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    threat_contained: bool = False
    actions_taken: int = 0
    response_time_ms: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
