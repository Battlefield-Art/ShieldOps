"""State models for the Security Orchestration Hub Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SOHStage(StrEnum):
    """Stages in the security orchestration lifecycle."""

    INGEST_EVENT = "ingest_event"
    CLASSIFY_SEVERITY = "classify_severity"
    ROUTE_PLAYBOOK = "route_playbook"
    EXECUTE_ACTIONS = "execute_actions"
    VALIDATE_OUTCOME = "validate_outcome"
    REPORT = "report"


class EventSeverity(StrEnum):
    """Security event severity classifications."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PlaybookCategory(StrEnum):
    """Categories of orchestration playbooks."""

    INCIDENT_RESPONSE = "incident_response"
    THREAT_CONTAINMENT = "threat_containment"
    VULNERABILITY_REMEDIATION = "vulnerability_remediation"
    COMPLIANCE_ENFORCEMENT = "compliance_enforcement"
    ACCESS_REVOCATION = "access_revocation"
    FORENSIC_COLLECTION = "forensic_collection"


# --- Domain models ---


class SecurityEvent(BaseModel):
    """An ingested security event to orchestrate."""

    event_id: str = ""
    source: str = ""
    event_type: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    tenant_id: str = ""


class SeverityClassification(BaseModel):
    """Result of severity classification for an event."""

    event_id: str = ""
    original_severity: str = ""
    classified_severity: EventSeverity = EventSeverity.MEDIUM
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    escalation_required: bool = False


class PlaybookRoute(BaseModel):
    """Selected playbook and routing decision."""

    playbook_id: str = ""
    category: PlaybookCategory = PlaybookCategory.INCIDENT_RESPONSE
    steps: list[str] = Field(default_factory=list)
    estimated_duration_ms: int = 0
    auto_approved: bool = False


class ActionResult(BaseModel):
    """Result from executing an orchestrated action."""

    action_id: str = ""
    action_type: str = ""
    status: str = "pending"
    output: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
    error: str = ""


class OutcomeValidation(BaseModel):
    """Validation of orchestration outcome."""

    validated: bool = False
    success_rate: float = 0.0
    actions_completed: int = 0
    actions_failed: int = 0
    rollback_needed: bool = False
    summary: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityOrchestrationHubState(BaseModel):
    """Full state for a security orchestration hub run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SOHStage = SOHStage.INGEST_EVENT

    # Inputs
    event_source: str = ""
    event_type: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    playbook_routes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    action_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    severity: EventSeverity = EventSeverity.MEDIUM
    actions_executed: int = 0
    actions_succeeded: int = 0
    outcome_validated: bool = False

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
