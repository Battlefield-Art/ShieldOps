"""State models for the Security Automation Hub Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SAHStage(StrEnum):
    """Stages of the security automation hub lifecycle."""

    INGEST_TRIGGERS = "ingest_triggers"
    MATCH_PLAYBOOKS = "match_playbooks"
    EXECUTE_AUTOMATIONS = "execute_automations"
    VALIDATE_RESULTS = "validate_results"
    LEARN_OUTCOMES = "learn_outcomes"
    REPORT = "report"


class TriggerType(StrEnum):
    """Types of security triggers that initiate automation."""

    ALERT = "alert"
    INCIDENT = "incident"
    POLICY_VIOLATION = "policy_violation"
    THREAT_INTEL = "threat_intel"
    ANOMALY = "anomaly"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    WEBHOOK = "webhook"


class AutomationStatus(StrEnum):
    """Status of an automation execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_APPROVAL = "requires_approval"
    ROLLED_BACK = "rolled_back"
    TIMED_OUT = "timed_out"


class SecurityTrigger(BaseModel):
    """A security event that triggers automation."""

    trigger_id: str = ""
    trigger_type: TriggerType = TriggerType.ALERT
    source: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    tenant_id: str = ""


class PlaybookMatch(BaseModel):
    """A playbook matched to a trigger."""

    match_id: str = ""
    trigger_id: str = ""
    playbook_name: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    actions: list[str] = Field(default_factory=list)
    estimated_duration_ms: int = 0
    requires_approval: bool = False


class AutomationExecution(BaseModel):
    """Result of an automation execution."""

    execution_id: str = ""
    playbook_name: str = ""
    trigger_id: str = ""
    status: AutomationStatus = AutomationStatus.PENDING
    actions_completed: int = 0
    actions_total: int = 0
    duration_ms: int = 0
    output: dict[str, Any] = Field(default_factory=dict)
    error: str = ""


class ValidationResult(BaseModel):
    """Validation of automation execution results."""

    validation_id: str = ""
    execution_id: str = ""
    passed: bool = True
    checks_passed: int = 0
    checks_total: int = 0
    issues: list[str] = Field(default_factory=list)


class LearningOutcome(BaseModel):
    """Learning outcome from automation execution."""

    outcome_id: str = ""
    execution_id: str = ""
    effectiveness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    lessons: list[str] = Field(default_factory=list)
    recommended_changes: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityAutomationHubState(BaseModel):
    """Full LangGraph state for the Security Automation Hub agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: SAHStage = SAHStage.INGEST_TRIGGERS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    triggers: list[dict[str, Any]] = Field(default_factory=list)
    playbook_matches: list[dict[str, Any]] = Field(default_factory=list)
    executions: list[dict[str, Any]] = Field(default_factory=list)
    validations: list[dict[str, Any]] = Field(default_factory=list)
    learnings: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    trigger_count: int = 0
    automation_count: int = 0
    success_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
